"""Read-only QNX6 filesystem extraction without mounting the image.

On-disk layout reference: Linux include/linux/qnx6_fs.h and fs/qnx6.
Only little-endian standard QNX6 is supported. Both superblock CRCs and long
filename checksums are checked. Symlinks/devices are recorded, never created.
This is an inspection reader, not a filesystem repair or firmware writer.
"""

import argparse
from functools import lru_cache
import hashlib
import json
import mmap
from pathlib import Path, PurePosixPath
import stat
import struct

from inspect_firmware import separate_output


def crc32_be(data):
    crc = 0
    for value in data:
        crc ^= value << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x04c11db7 if crc & 0x80000000 else 0)) & 0xffffffff
    return crc


class Qnx6:
    def __init__(self, data):
        self.data = data
        first = data[8192:8704]
        if len(first) != 512 or struct.unpack_from('<I', first)[0] != 0x68191122:
            raise ValueError('Expected standard little-endian QNX6 superblock at 8192')
        self.blocksize, self.inode_count, _, self.block_count = struct.unpack_from('<IIII', first, 48)
        if self.blocksize not in (512, 1024, 2048, 4096):
            raise ValueError('Unsupported block size')
        self.data_offset = 8192 + 4096
        second_offset = self.data_offset + self.block_count * self.blocksize
        second = data[second_offset:second_offset + 512]
        superblocks = [first, second]
        for sb in superblocks:
            if len(sb) != 512 or struct.unpack_from('<I', sb)[0] != 0x68191122 or crc32_be(sb[8:]) != struct.unpack_from('<I', sb, 4)[0]:
                raise ValueError('Invalid QNX6 superblock CRC or magic')
        self.sb = max(superblocks, key=lambda sb: struct.unpack_from('<Q', sb, 8)[0])
        self.inode_tree = self.root_node(self.sb[72:152])
        self.long_names = self.root_node(self.sb[232:312])
        self.metadata = {'blocksize': self.blocksize, 'blocks': self.block_count,
                         'inode_capacity': self.inode_count, 'superblocks_crc_valid': True,
                         'superblock_serials': [struct.unpack_from('<Q', sb, 8)[0] for sb in superblocks]}

    @staticmethod
    def root_node(record):
        return {'bytes': struct.unpack_from('<Q', record)[0],
                'pointers': struct.unpack_from('<16I', record, 8), 'levels': record[72]}

    @lru_cache(maxsize=8192)
    def block(self, number):
        if not 0 <= number < self.block_count:
            raise ValueError('Filesystem pointer outside data area')
        offset = self.data_offset + number * self.blocksize
        return self.data[offset:offset + self.blocksize]

    def node_block(self, node, logical):
        depth = node['levels']
        if depth > 5:
            raise ValueError('Too many indirect levels')
        per_block = self.blocksize // 4
        divisor = per_block ** depth
        top, remaining = divmod(logical, divisor)
        if top >= 16:
            raise ValueError('Logical block outside pointer tree')
        pointer = node['pointers'][top]
        for _ in range(depth):
            divisor //= per_block
            index, remaining = divmod(remaining, divisor)
            pointer = struct.unpack_from('<I', self.block(pointer), index * 4)[0]
        return self.block(pointer)

    def read_node(self, node, offset, size):
        if offset < 0 or offset + size > node['bytes']:
            raise ValueError('Read outside inode size')
        parts = []
        while size:
            logical, local = divmod(offset, self.blocksize)
            amount = min(self.blocksize - local, size)
            parts.append(self.node_block(node, logical)[local:local + amount])
            offset += amount
            size -= amount
        return b''.join(parts)

    @lru_cache(maxsize=8192)
    def inode(self, number):
        if not 1 <= number <= self.inode_count:
            raise ValueError('Inode outside table')
        record = self.read_node(self.inode_tree, (number - 1) * 128, 128)
        size, uid, gid = struct.unpack_from('<QII', record)
        return {'inode': number, 'bytes': size, 'uid': uid, 'gid': gid,
                'mode': struct.unpack_from('<H', record, 32)[0],
                'pointers': struct.unpack_from('<16I', record, 36), 'levels': record[100],
                'status': record[101]}

    def entries(self, node):
        data = self.read_node(node, 0, node['bytes'])
        if len(data) % 32:
            raise ValueError('Directory size is not a multiple of 32')
        for offset in range(0, len(data), 32):
            record = data[offset:offset + 32]
            number = struct.unpack_from('<I', record)[0]
            length = record[4]
            if not number or not length:
                continue
            if length <= 27:
                raw_name = record[5:5 + length]
            elif length == 255:
                block, expected = struct.unpack_from('<II', record, 8)
                location = block * self.blocksize
                length = struct.unpack('<H', self.read_node(self.long_names, location, 2))[0]
                if not 1 <= length <= 510:
                    raise ValueError('Invalid long filename length')
                raw_name = self.read_node(self.long_names, location + 2, length)
                checksum = 0
                for value in raw_name:
                    checksum = (((checksum >> 1) + value) ^ (0x80000000 if checksum & 1 else 0)) & 0xffffffff
                if checksum != expected:
                    raise ValueError('Long filename checksum mismatch')
            else:
                raise ValueError('Unsupported directory entry')
            name = raw_name.decode('utf-8')
            if name in ('.', '..'):
                continue
            if '/' in name or '\\' in name or ':' in name or '\0' in name:
                raise ValueError('Unsafe filesystem component')
            yield name, number


def extract(source, output):
    output = separate_output(source.parent, output)
    with source.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        filesystem = Qnx6(data)
        output.mkdir(parents=True, exist_ok=False)
        root = output / 'files'
        root.mkdir()
        manifest = []

        def visit(number, relative, ancestors):
            node = filesystem.inode(number)
            if len(ancestors) > 64:
                raise ValueError('Directory nesting limit exceeded')
            entry = {k: v for k, v in node.items() if k not in ('pointers', 'levels')}
            entry.update(path=relative, mode=oct(node['mode']))
            target = root.joinpath(*PurePosixPath(relative).parts)
            if not target.resolve().is_relative_to(root.resolve()):
                raise ValueError('Extraction path escaped output')
            if stat.S_ISDIR(node['mode']):
                if number in ancestors:
                    raise ValueError('Directory cycle')
                entry['type'] = 'directory'
                if relative:
                    target.mkdir()
                manifest.append(entry)
                for name, child in filesystem.entries(node):
                    visit(child, relative + '/' + name if relative else name, ancestors | {number})
                return
            if stat.S_ISREG(node['mode']):
                entry['type'] = 'file'
                digest = hashlib.sha256()
                with target.open('xb') as dest:
                    for offset in range(0, node['bytes'], 1024 * 1024):
                        chunk = filesystem.read_node(node, offset, min(1024 * 1024, node['bytes'] - offset))
                        dest.write(chunk)
                        digest.update(chunk)
                entry['sha256'] = digest.hexdigest()
            elif stat.S_ISLNK(node['mode']):
                entry.update(type='symlink', target=filesystem.read_node(node, 0, node['bytes']).decode('utf-8'))
            else:
                entry['type'] = 'other'
            manifest.append(entry)

        visit(1, '', set())
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        (output / 'filesystem.json').write_text(json.dumps(filesystem.metadata, indent=2) + '\n', encoding='utf-8')
        print(f'Inventoried {len(manifest)} QNX6 entries; extracted regular files to {root}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    extract(args.source, args.output)


if __name__ == '__main__':
    main()
