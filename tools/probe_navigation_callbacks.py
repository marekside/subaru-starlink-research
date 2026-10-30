"""Bounded offline probes of three stock navigation callback dispatch functions.

Runs only hash-pinned ARM dispatch code in Unicorn, with synthetic arguments.
The logging-level helper and our dummy callback are intercepted. All unexpected
code paths/interrupts fail closed. No QNX process, hardware or network is used.
Results describe machine-word forwarding, not a complete typed Cinemo SDK ABI.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                              UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                              UC_ARM_REG_CPSR, UC_ARM_REG_R15)

from arm_inspect import ArmElf
from verify_android_auto_transport import AA_HASH


class CallbackProbe:
    OBJECT, STACK, INPUT, CALLBACK, STOP = 0x10000000, 0x11000000, 0x12000000, 0x13000000, 0x13001000
    CONTEXT = 0x12345678
    DISPATCH = {'status': (0x3fb68, 0x3fcb4, 0x1350, 2),
                'next_turn': (0x3fce4, 0x3fe48, 0x1354, 8),
                'distance': (0x3fe70, 0x40030, 0x1358, 5)}

    def __init__(self, receiver):
        self.elf = ArmElf(receiver, arm=True)
        if hashlib.sha256(self.elf.data).hexdigest() != AA_HASH:
            raise ValueError('Unsupported receiver hash; refusing to execute')
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        pages = set()
        for segment in self.elf.loads:
            first = segment['p_vaddr'] & ~4095
            end = (segment['p_vaddr'] + segment['p_memsz'] + 4095) & ~4095
            pages.update(range(first, end, 4096))
        for page in sorted(pages):
            self.uc.mem_map(page, 4096)
        for segment in self.elf.loads:
            if segment['p_filesz']:
                self.uc.mem_write(segment['p_vaddr'], self.elf.read(segment['p_vaddr'], segment['p_filesz']))
        # Dispatch probes do not need to write any original firmware page.
        for page in pages:
            self.uc.mem_protect(page, 4096, UC_PROT_READ | UC_PROT_EXEC)
        for base in (self.OBJECT, self.STACK, self.INPUT):
            self.uc.mem_map(base, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(self.CALLBACK, 0x2000, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt)
        self.active = None

    @staticmethod
    def _interrupt(*_):
        raise ValueError('Unexpected interrupt in isolated dispatch probe')

    def _code(self, uc, address, size, _):
        if address == self.STOP:
            self.finished = True
            uc.emu_stop()
        elif address == 0x16ff0:
            # NmeInterlockedRead: synthetic high threshold skips all logging calls.
            uc.reg_write(UC_ARM_REG_R0, 10)
            uc.reg_write(UC_ARM_REG_R15, uc.reg_read(UC_ARM_REG_LR))
        elif address == self.CALLBACK:
            registers = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            count = self.active[3]
            extra = max(0, count - 4)
            stack = list(struct.unpack('<' + 'I' * extra, uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 4 * extra))) if extra else []
            self.calls.append((registers + stack)[:count])
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_R15, uc.reg_read(UC_ARM_REG_LR))
        elif not self.active[0] <= address < self.active[1]:
            raise ValueError(f'Unexpected execution at {address:#x}')

    def _word(self, address, value):
        self.uc.mem_write(address, struct.pack('<I', value & 0xffffffff))

    def run(self, kind, words, stack_words=(), registered=True):
        if kind not in self.DISPATCH or len(words) != 3 or len(stack_words) > 3:
            raise ValueError('Invalid probe request')
        self.active = self.DISPATCH[kind]
        self.calls, self.finished = [], False
        self.uc.mem_write(self.OBJECT, bytes(0x2000))
        self.uc.mem_write(self.STACK, bytes(0x10000))
        self._word(self.OBJECT + 0x1300, self.CONTEXT)
        self._word(self.OBJECT + self.active[2], self.CALLBACK if registered else 0)
        # ARM state, known flags and a fresh synthetic call stack for each probe.
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x10)
        for reg, word in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), (self.OBJECT, *words)):
            self.uc.reg_write(reg, word & 0xffffffff)
        sp = self.STACK + 0x8000
        for index, value in enumerate(stack_words):
            self._word(sp + index * 4, value)
        self.uc.reg_write(UC_ARM_REG_SP, sp)
        self.uc.reg_write(UC_ARM_REG_LR, self.STOP)
        self.uc.emu_start(self.active[0], self.STOP + 4, timeout=1000000, count=10000)
        if not self.finished:
            raise ValueError('Probe exceeded its execution budget')
        return self.calls

    def next_turn(self, side, maneuver, registered=True):
        road, road_ref = self.INPUT + 0x100, self.INPUT
        image, image_ref = self.INPUT + 0x200, self.INPUT + 4
        self.uc.mem_write(road, b'synthetic road\0')
        self._word(road_ref, road)
        self.uc.mem_write(image, b'IMG')
        self._word(image - 12, 3)  # Only the string-length word this dispatch reads.
        self._word(image_ref, image)
        return self.run('next_turn', [road_ref, side, maneuver], [image_ref, 0x55, 0x66], registered)


def probe(receiver):
    p = CallbackProbe(receiver)
    statuses = {str(n): p.run('status', [n, 0, 0]) for n in (0, 1, 2, 3, 0xffffffff)}
    distances = {str(n): p.run('distance', [0x1111, 0x2222, 0x3333], [n]) for n in range(9)}
    turns = {str(n): p.next_turn(1, n) for n in range(21)}
    sides = {str(n): p.next_turn(n, 1)[0][2] for n in range(4)}
    missing = {'status': p.run('status', [1, 0, 0], registered=False),
               'next_turn': p.next_turn(1, 1, registered=False),
               'distance': p.run('distance', [1, 2, 3], [1], registered=False)}
    return {'receiver_sha256': AA_HASH, 'mode': 'isolated_synthetic_dispatch_probe',
            'status_words': statuses, 'distance_words': distances,
            'next_turn_words': turns, 'side_enum_mapping': sides,
            'missing_callbacks': missing,
            'limits': ['No full QNX emulation or on-unit execution',
                       'Synthetic input words are not typed SDK declarations or physical units',
                       'Only dummy logging-level helper and dummy callback are allowed outside dispatch functions',
                       'All original firmware pages are read-only; no OS services/devices are emulated']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receiver', type=Path, default=Path('analysis/rel-a2.25.15.20/second1/files/second1/MediaOne/cinemo/libNmeAndroidAuto.so'))
    args = parser.parse_args()
    print(json.dumps(probe(args.receiver), indent=2))
