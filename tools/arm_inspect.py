"""Read-only ARM ELF inspection, including QNX imagefs-processed ELF files.

Requires capstone and pyelftools. Non-LOAD program-header file offsets may be
stale after imagefs processing: resolve virtual addresses through PT_LOAD.
"""

from pathlib import Path
import argparse
import bisect
import json
import re
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
from elftools.elf.elffile import ELFFile


class ArmElf:
    def __init__(self, path, arm=False):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        with self.path.open("rb") as stream:
            elf = ELFFile(stream)
            if elf['e_machine'] != 'EM_ARM' or not elf.little_endian or elf.elfclass != 32:
                raise ValueError('Expected little-endian ELF32 ARM')
            self.segments = [dict(s.header) for s in elf.iter_segments()]
            self.entry = elf['e_entry']
        self.loads = [s for s in self.segments if s['p_type'] == 'PT_LOAD']
        self.tags = {}
        for segment in self.segments:
            if segment['p_type'] == 'PT_DYNAMIC':
                for tag, value in struct.iter_unpack('<II', self.read(segment['p_vaddr'], segment['p_filesz'])):
                    if not tag:
                        break
                    self.tags[tag] = value
        self.symbols = []
        if 6 in self.tags:
            if 4 in self.tags:
                count = self.u32(self.tags[4] + 4)
            else:
                gnu = self.tags[0x6ffffef5]
                buckets, first_symbol, bloom, _ = struct.unpack('<IIII', self.read(gnu, 16))
                bucket_base = gnu + 16 + bloom * 4
                values = struct.unpack('<' + 'I' * buckets, self.read(bucket_base, buckets * 4))
                index = max(values, default=0)
                count = first_symbol
                if index:
                    chain = bucket_base + buckets * 4
                    while not self.u32(chain + (index - first_symbol) * 4) & 1:
                        index += 1
                    count = index + 1
            strings = self.read(self.tags[5], self.tags[10])
            for index in range(count):
                name, value, size, info, other, section = struct.unpack('<IIIBBH', self.read(self.tags[6] + index * 16, 16))
                self.symbols.append({'name': strings[name:].split(b'\0')[0].decode(),
                                     'value': value, 'bytes': size})
        self.relocations = {}
        if 17 in self.tags:
            for offset, info in struct.iter_unpack('<II', self.read(self.tags[17], self.tags[18])):
                symbol_index = info >> 8
                if symbol_index:
                    self.relocations[offset] = self.symbols[symbol_index]['name']
        if 23 in self.tags:
            for offset, info in struct.iter_unpack('<II', self.read(self.tags[23], self.tags[2])):
                self.relocations[offset] = self.symbols[info >> 8]['name']
        self.functions = []
        for segment in self.segments:
            if segment['p_type'] == 'PT_ARM_EXIDX':
                base = segment['p_vaddr']
                for offset in range(0, segment['p_filesz'], 8):
                    word = self.u32(base + offset) & 0x7fffffff
                    if word & 0x40000000:
                        word -= 0x80000000
                    self.functions.append((base + offset + word) & ~1)
        self.functions = sorted(set(self.functions))
        self.decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM if arm else CS_MODE_THUMB)
        self.decoder.detail = True
        self.decoder.skipdata = True

    def read(self, address, size):
        for segment in self.loads:
            if segment['p_vaddr'] <= address and address + size <= segment['p_vaddr'] + segment['p_filesz']:
                start = segment['p_offset'] + address - segment['p_vaddr']
                return self.data[start:start + size]
        raise ValueError(f'Unmapped address {address:#x}, size {size:#x}')

    def u32(self, address):
        return struct.unpack('<I', self.read(address, 4))[0]

    def strings(self, pattern):
        matches = []
        for segment in self.loads:
            data = self.read(segment['p_vaddr'], segment['p_filesz'])
            for match in re.finditer(rb'[ -~]{6,}', data):
                text = match[0].decode()
                if re.search(pattern, text, re.I):
                    matches.append({'address': segment['p_vaddr'] + match.start(), 'text': text})
        return matches

    def function_at(self, address):
        index = bisect.bisect_right(self.functions, address) - 1
        return self.functions[index] if index >= 0 else None

    def instructions(self, start, end):
        return self.decoder.disasm(self.read(start, end - start), start)

    def import_name(self, address):
        try:
            first, second, third = struct.unpack('<III', self.read(address & ~1, 12))
        except ValueError:
            return None
        if first & 0xfffff000 != 0xe28fc000 or second & 0xfffff000 != 0xe28cc000 or third & 0xfffff000 != 0xe5bcf000:
            return None
        def immediate(word):
            value, rotate = word & 255, ((word >> 8) & 15) * 2
            return ((value >> rotate) | (value << (32 - rotate))) & 0xffffffff if rotate else value
        slot = (address & ~1) + 8 + immediate(first) + immediate(second) + (third & 4095)
        return self.relocations.get(slot)

    def annotation(self, ins):
        if not ins.id:
            return ''
        if ins.mnemonic in ('bl', 'blx', 'b', 'b.w') and ins.operands[0].type == ARM_OP_IMM:
            name = self.import_name(ins.operands[0].imm)
            if name:
                return ' ; ' + name
        if ins.mnemonic.startswith('ldr') and len(ins.operands) > 1 and ins.operands[1].type == ARM_OP_MEM and ins.operands[1].mem.base == ARM_REG_PC:
            literal = ((ins.address + (8 if self.decoder.mode == CS_MODE_ARM else 4)) & ~3) + ins.operands[1].mem.disp
            try:
                value = self.u32(literal)
                text = self.read(value, 120).split(b'\0')[0]
                if text and all(32 <= c < 127 for c in text):
                    return f' ; {value:#x} {text.decode()!r}'
                return f' ; {value:#x}'
            except ValueError:
                return ''
        return ''

    def xrefs(self, pattern):
        targets = self.strings(pattern)
        by_address = {x['address']: x for x in targets}
        # Include pointers in GOT/data, used by literal LDR followed by indirection.
        pointers = {}
        for segment in self.loads:
            for offset in range(0, segment['p_filesz'] - 3, 4):
                address = segment['p_vaddr'] + offset
                value = self.u32(address)
                if value in by_address:
                    pointers[address] = by_address[value]
        refs = []
        ranges = list(zip(self.functions, self.functions[1:]))
        if not ranges and 12 in self.tags and 13 in self.tags:
            ranges = [(self.tags[12] & ~1, self.tags[13] & ~1)]
        for start, end in ranges:
            try:
                instructions = self.instructions(start, end)
                for ins in instructions:
                    if ins.id == 0 or not ins.mnemonic.startswith('ldr') or len(ins.operands) < 2:
                        continue
                    op = ins.operands[1]
                    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
                        continue
                    pc_bias = 8 if self.decoder.mode == CS_MODE_ARM else 4
                    literal = ((ins.address + pc_bias) & ~3) + op.mem.disp
                    try:
                        value = self.u32(literal)
                    except ValueError:
                        continue
                    target = by_address.get(value) or pointers.get(value)
                    if target:
                        function = self.function_at(ins.address)
                        refs.append({'instruction': hex(ins.address), 'function': hex(function) if function else None,
                                     'target': hex(target['address']), 'text': target['text']})
            except ValueError:
                continue
        return {'strings': targets, 'literal_xrefs': refs,
                'note': 'Literal-load matches only; absence does not establish no references.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--strings')
    parser.add_argument('--xrefs')
    parser.add_argument('--arm', action='store_true', help='Decode ARM instructions (default Thumb)')
    parser.add_argument('--start', type=lambda x: int(x, 0))
    parser.add_argument('--end', type=lambda x: int(x, 0))
    args = parser.parse_args()
    elf = ArmElf(args.elf, arm=args.arm)
    if args.strings:
        print(json.dumps(elf.strings(args.strings), indent=2))
    elif args.xrefs:
        print(json.dumps(elf.xrefs(args.xrefs), indent=2))
    elif args.start is not None and args.end is not None:
        for ins in elf.instructions(args.start, args.end):
            print(f'{ins.address:08x}: {ins.mnemonic:9s} {ins.op_str}{elf.annotation(ins)}')
    else:
        print(json.dumps({'entry': hex(elf.entry), 'function_boundaries': len(elf.functions),
                          'imports': [x['name'] for x in elf.symbols if not x['value']],
                          'relocations': {hex(k): v for k, v in elf.relocations.items()}}, indent=2))


if __name__ == '__main__':
    main()
