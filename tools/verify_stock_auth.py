"""Verify the supplied ISO signature and its bindings to CNDFS metadata.

Trust is relative to the supplied public key, not an independently obtained OEM
trust anchor. This does not test the head unit's verifier or establish recovery.
Encrypted payload data also needs per-cluster AES-GCM verification (extract_cndfs).
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from inspect_firmware import separate_output

REFERENCE_OFFSETS = {'system.dat': 0x11a, 'swupdate.dat': 0x13a,
                     'navsw.dat': 0x15a, 'misc.dat': 0x17a, 'gracenote.dat': 0x19a}


def verify_cndfs_metadata(source):
    with source.open('rb') as stream:
        header = stream.read(512)
        if len(header) != 512 or header[:8] != b'QNXCNDFS':
            raise ValueError('Invalid CNDFS header')
        if struct.unpack_from('<II', header, 0x58) != (4, 4):
            raise ValueError('Only SHA-256 header and metadata hashes supported')
        expected = header[0x68:0x88]
        if hashlib.sha256(header[:0x68] + bytes(32) + header[0x88:]).digest() != expected:
            raise ValueError('CNDFS header hash mismatch')
        extents, clusters, data_start, extent_count, cluster_count = struct.unpack_from('<QQQQQ', header, 0x28)
        if not (512 <= extents <= clusters <= data_start <= source.stat().st_size and
                extent_count <= 10000 and cluster_count <= 10000 and
                extents + extent_count * 32 <= clusters and clusters + cluster_count * 16 <= data_start):
            raise ValueError('Invalid CNDFS table bounds')
        stream.seek(extents)
        if hashlib.sha256(stream.read(extent_count * 32)).digest() != header[0xa8:0xc8]:
            raise ValueError('CNDFS extent-table hash mismatch')
        stream.seek(clusters)
        if hashlib.sha256(stream.read(cluster_count * 16)).digest() != header[0xe8:0x108]:
            raise ValueError('CNDFS cluster-table hash mismatch')
        return {'payload': source.name, 'header_sha256': expected.hex(),
                'header_hash_valid': True, 'extent_table_hash_valid': True,
                'cluster_table_hash_valid': True}


def verify(source, public_key, output):
    separate_output(source, output)
    separate_output(public_key.parent, output)
    iso = (source / 'swdl.iso').read_bytes()
    if len(iso) < 0x8000:
        raise ValueError('Truncated ISO')
    key = RSA.import_key(public_key.read_bytes()).public_key()
    if key.size_in_bits() != 2048:
        raise ValueError('Expected the analyzed RSA-2048 firmware public key')
    pkcs1_15.new(key).verify(SHA256.new(iso[0x100:0x8000]), iso[:0x100])
    if hashlib.sha256(iso[0x8000:]).digest() != iso[0x7fe0:0x8000]:
        raise ValueError('ISO body hash mismatch')
    payloads = []
    for name, offset in REFERENCE_OFFSETS.items():
        entry = verify_cndfs_metadata(source / name)
        if iso[offset:offset + 32].hex() != entry['header_sha256']:
            raise ValueError(f'Signed ISO reference mismatch: {name}')
        entry.update(iso_reference_offset=hex(offset), signed_reference_matches=True)
        payloads.append(entry)
    result = {'iso_signature_valid': True, 'algorithm': 'RSA-2048-PKCS1v1.5-SHA256',
              'signed_range': ['0x100', '0x8000'], 'iso_body_hash_valid': True,
              'public_key_der_sha256': hashlib.sha256(key.export_key(format='DER')).hexdigest(),
              'trust_anchor': 'Public key extracted from supplied firmware; not independently authenticated',
              'payloads': payloads}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(f'ISO signature/body and all {len(payloads)} payload metadata bindings verified')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--public-key', type=Path, default=Path('analysis/mainifs/files/etc/keys/SubaruPubkey.pmem'))
    args = parser.parse_args()
    verify(args.source, args.public_key, args.output)


if __name__ == '__main__':
    main()
