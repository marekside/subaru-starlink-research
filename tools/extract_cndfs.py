"""Offline extraction of this stock build's encrypted QNXCNDFS payloads.

No repacking, flashing, device access or authentication bypass. AES-GCM tags
are verified. LZO1C decoding uses a hash-pinned routine from the supplied
cdqnx6fs under Unicorn; the QNX program is never launched. Keys stay in memory.
CNDFS metadata hashes are verified. Run verify_stock_auth.py separately for
the ISO signature and signed payload-reference bindings.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from Crypto.Cipher import AES
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

from arm_inspect import ArmElf
from inspect_firmware import separate_output
from verify_stock_auth import verify_cndfs_metadata

DECODER_SHA256 = '5b0e4ab76598f46b36b840a1849bfee5abdf66c0bc124cd61d7c1c1ba3e91bdc'


class LzoDecoder:
    def __init__(self, path):
        if hashlib.sha256(path.read_bytes()).hexdigest() != DECODER_SHA256:
            raise ValueError('Decoder binary does not match the analyzed stock build')
        elf = ArmElf(path)
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        for segment in elf.loads:
            base = segment['p_vaddr'] & ~4095
            end = (segment['p_vaddr'] + segment['p_memsz'] + 4095) & ~4095
            self.uc.mem_map(base, end - base)
            self.uc.mem_write(segment['p_vaddr'], elf.read(segment['p_vaddr'], segment['p_filesz']))
        self.source, self.dest, self.stack, self.stop = 0x10000000, 0x11000000, 0x12000000, 0x13000000
        for address, size in [(self.source, 0x200000), (self.dest, 0x200000), (self.stack, 0x10000), (self.stop, 4096)]:
            self.uc.mem_map(address, size)
        self.uc.hook_add(UC_HOOK_CODE, self.memcpy, begin=0x80494b4, end=0x80494b4)
        self.uc.hook_add(UC_HOOK_INTR, self.no_interrupt)

    def no_interrupt(self, *args):
        raise ValueError('Unexpected firmware interrupt during pure decompression')

    def memcpy(self, uc, address, size, user_data):
        dest, source, length = (uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        if not (self.dest <= dest <= self.dest + 0x200000 - length and
                self.source <= source <= self.source + 0x200000 - length):
            raise ValueError('Decompressor requested out-of-buffer memcpy')
        uc.mem_write(dest, bytes(uc.mem_read(source, length)))
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def decompress(self, data, maximum):
        if not 0 < maximum <= 0x100000 or len(data) > 0x200000:
            raise ValueError('Unsupported decompression size')
        uc = self.uc
        uc.mem_write(self.source, data)
        uc.mem_write(self.stack, struct.pack('<I', maximum))
        for reg, value in [(UC_ARM_REG_R0, self.source), (UC_ARM_REG_R1, len(data)),
                           (UC_ARM_REG_R2, self.dest), (UC_ARM_REG_R3, self.stack),
                           (UC_ARM_REG_SP, self.stack + 0xf000), (UC_ARM_REG_LR, self.stop | 1)]:
            uc.reg_write(reg, value)
        uc.emu_start(0x80517ed, self.stop, timeout=10000000, count=20000000)
        length = struct.unpack('<I', uc.mem_read(self.stack, 4))[0]
        if uc.reg_read(UC_ARM_REG_PC) != self.stop or uc.reg_read(UC_ARM_REG_R0) != 0 or length > maximum:
            raise ValueError('LZO decoder failed or exceeded execution budget')
        return bytes(uc.mem_read(self.dest, length))


def payload_key(iso, keyfile):
    with iso.open('rb') as stream:
        stream.seek(0x7fde)
        digits = stream.read(2)
    if len(digits) != 2 or not digits.isdigit():
        raise ValueError('Invalid package salt')
    salt = int(digits)
    original = keyfile.read_text(encoding='ascii')
    if len(original) != 64 or any(c not in '0123456789ABCDEF' for c in original):
        raise ValueError('Expected the stock 64-character hex key file')
    transformed = ''.join('0123456789ABCDEF'[(int(c, 16) + (salt if i % 2 == 0 else -salt)) % 16]
                          for i, c in enumerate(original))
    return bytes.fromhex(transformed)


def extract(source, iso, keyfile, decoder, output):
    for path in (source, iso, keyfile, decoder):
        separate_output(path.parent, output)
    verify_cndfs_metadata(source)
    size = source.stat().st_size
    with source.open('rb') as stream:
        header = stream.read(512)
        if header[:8] != b'QNXCNDFS' or struct.unpack_from('<I', header, 12)[0] != 3:
            raise ValueError('Only encrypted/compressed CNDFS flags=3 supported')
        raw_size, stored_size, data_size, extent_table, cluster_table, data_start, extent_count, cluster_count = struct.unpack_from('<QQQQQQQQ', header, 16)
        cluster_size = struct.unpack_from('<I', header, 80)[0]
        if stored_size != size or raw_size > 4 * 1024**3 or not 0 < cluster_size <= 0x100000:
            raise ValueError('Unsupported payload sizes')
        if not (512 <= extent_table <= cluster_table <= data_start <= size and
                extent_count <= 10000 and cluster_count <= 10000 and
                extent_table + extent_count * 32 <= cluster_table and
                cluster_table + cluster_count * 16 <= data_start):
            raise ValueError('Invalid CNDFS metadata bounds')
        stream.seek(extent_table)
        extents = list(struct.iter_unpack('<QQQQ', stream.read(extent_count * 32)))
        stream.seek(cluster_table)
        clusters = list(struct.iter_unpack('<QQ', stream.read(cluster_count * 16)))
        if sum(e[1] for e in extents) != data_size:
            raise ValueError('Extent lengths do not match declared data size')
        for dest, length, cluster_entry, cluster_offset in extents:
            if dest + length > raw_size or cluster_entry < cluster_table or (cluster_entry - cluster_table) % 16 or cluster_entry >= cluster_table + cluster_count * 16 or cluster_offset >= cluster_size:
                raise ValueError('Invalid extent')
        for (dest, length, _, _), (next_dest, _, _, _) in zip(extents, extents[1:]):
            if dest + length > next_dest:
                raise ValueError('Overlapping or unordered extents')
        key = payload_key(iso, keyfile)
        lzo = LzoDecoder(decoder)
        output.mkdir(parents=True, exist_ok=False)
        raw_path = output / 'filesystem.qnx6'
        consumed = 0
        extent_index = 0
        extent_used = 0
        with raw_path.open('xb') as target:
            target.truncate(raw_size)
            for index, (position, length) in enumerate(clusters):
                if position < data_start or length < 32 or position + length > size:
                    raise ValueError('Cluster outside payload')
                stream.seek(position)
                cluster = stream.read(length)
                plaintext = AES.new(key, AES.MODE_GCM, nonce=cluster[:16]).decrypt_and_verify(cluster[32:], cluster[16:32])
                expected = min(cluster_size, data_size - consumed)
                raw = lzo.decompress(plaintext, expected)
                if len(raw) != expected:
                    raise ValueError('Raw cluster length mismatch')
                offset = 0
                while offset < len(raw):
                    dest, extent_length, entry, entry_offset = extents[extent_index]
                    if extent_used == 0 and (entry != cluster_table + index * 16 or entry_offset != offset):
                        raise ValueError('Extent start does not match cluster metadata')
                    amount = min(extent_length - extent_used, len(raw) - offset)
                    target.seek(dest + extent_used)
                    target.write(raw[offset:offset + amount])
                    offset += amount
                    extent_used += amount
                    if extent_used == extent_length:
                        extent_index += 1
                        extent_used = 0
                consumed += len(raw)
                if index % 32 == 0 or index + 1 == len(clusters):
                    print(f'{source.name}: authenticated/decompressed {index + 1}/{len(clusters)} clusters', flush=True)
        if consumed != data_size or extent_index != len(extents):
            raise ValueError('Incomplete extent restoration')
    metadata = {'source': source.name, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'raw_bytes': raw_size, 'populated_bytes': data_size,
                'authenticated_clusters': len(clusters), 'extents': extents,
                'decoder_sha256': DECODER_SHA256,
                'oem_signature_verified': False, 'cndfs_metadata_hashes_verified': True}
    (output / 'extraction.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--iso', type=Path, default=Path('usbUpdateStock/KaliSWDL/swdl.iso'))
    parser.add_argument('--keyfile', type=Path, default=Path('analysis/mainifs/files/etc/keys/symm.key'))
    parser.add_argument('--decoder', type=Path, default=Path('analysis/minifs/files/miniFS/bin/cdqnx6fs'))
    args = parser.parse_args()
    extract(args.source, args.iso, args.keyfile, args.decoder, args.output)


if __name__ == '__main__':
    main()
