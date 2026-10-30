"""Reproduce the static USB-only transport finding for the supplied stock build.

This is a hash-pinned audit, not a universal Cinemo capability detector. It
checks actual protocol-dispatch instructions and the constructed transport's
RTTI. It neither runs firmware nor tests radio hardware. Requires capstone and
pyelftools from requirements-firmware.txt.
"""

import argparse
import hashlib
import json
from pathlib import Path

from arm_inspect import ArmElf
from inspect_firmware import separate_output

AA_HASH = '32f5e8847c033a283bbfcc6b465d08b5ab6a4ee0a2d92b6cb51369346dae8a97'
GAL_HASH = '49b8f393b866773520f22c0e64e98d5c8df4bfc6e291ee70cfa2c71872dc8dde'


def instruction(elf, address, mnemonic, operands):
    ins = next(elf.instructions(address, address + 4))
    if (ins.mnemonic, ins.op_str) != (mnemonic, operands):
        raise ValueError(f'Unexpected instruction at {address:#x}: {ins.mnemonic} {ins.op_str}')


def cstring(elf, address):
    return elf.read(address, 96).split(b'\0')[0].decode('ascii')


def resolved_arm_literal(elf, load_address, displacement, add_pc_address):
    return (elf.u32(load_address + 8 + displacement) + add_pc_address + 8) & 0xffffffff


def verify(receiver, wrapper):
    for source, expected in [(receiver, AA_HASH), (wrapper, GAL_HASH)]:
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError(f'{source.name}: different binary; this audit applies only to the analyzed build')
    aa = ArmElf(receiver, arm=True)
    gal = ArmElf(wrapper)
    prefix = cstring(aa, resolved_arm_literal(aa, 0x2e46c, 0x808, 0x2e474))
    protocol = cstring(aa, resolved_arm_literal(aa, 0x2e4a8, 0x7d0, 0x2e4b0))
    if (prefix, protocol) != ('aoap', 'usb'):
        raise ValueError('Unexpected protocol constants')
    if aa.import_name(0x16dc8) != '_ZNK9NmeString12url_protocolEi' or aa.import_name(0x173e4) != '_ZNK9NmeString4cmpiEPKc':
        raise ValueError('Protocol extraction/comparison imports do not match')
    checks = [
        (0x2e4a4, 'bl', '#0x16dc8'),
        (0x2e4b4, 'bl', '#0x173e4'),
        (0x2e4b8, 'mov', 'r5, r0'),
        (0x2e4c4, 'cmp', 'r5, #0'),
        (0x2e4c8, 'beq', '#0x2e570'),
        (0x2e548, 'mov', 'r5, #0xb'),
        (0x2e570, 'add', 'r0, sp, #0x48'),
        (0x2e574, 'bl', '#0x16e4c'),
        (0x2e580, 'bl', '#0x2d590'),
        (0x2e160, 'bl', '#0x2b12c'),
        (0x2b224, 'bl', '#0x509ac'),
        (0x2b290, 'bl', '#0x4ea48'),
        (0x4eab4, 'bl', '#0x17640'),
    ]
    for address, mnemonic, operands in checks:
        instruction(aa, address, mnemonic, operands)
    if aa.import_name(0x17640) != '_ZN15NmeClassFactory12CreateUSBLibEPP10INmeUSBLib':
        raise ValueError('USB library creation import does not match')
    # Constructor stores the derived vtable at 0x50db0, after its base setup.
    vtable = resolved_arm_literal(aa, 0x50d90, 0x434, 0x50da0) + 8
    instruction(aa, 0x50db0, 'str', 'r2, [r4]')
    rtti = aa.u32(vtable - 4)
    transport_class = cstring(aa, aa.u32(rtti + 4))
    if transport_class != '26NmeAndroidAutoUSBTransport':
        raise ValueError('Constructed transport RTTI does not match')
    url_literal = ((0x19ffe + 4) & ~3) + 0x164
    url_prefix = cstring(gal, (gal.u32(url_literal) + 0x1a004 + 4) & 0xffffffff)
    if url_prefix != 'usb:///':
        raise ValueError('Subaru wrapper URL prefix does not match')
    imports = sorted({s['name'] for s in aa.symbols if not s['value']} &
                     {'socket', 'connect', 'accept', 'bind', 'listen', 'send', 'recv', 'getaddrinfo', 'dlopen', 'dlsym'})
    return {
        'firmware': 'EU High Rel_A2.24.41.20',
        'method': 'Static protocol control flow and constructor/RTTI review, reproduced against hash-pinned binaries',
        'receiver_sha256': AA_HASH, 'wrapper_sha256': GAL_HASH,
        'receiver_session_transport': 'USB only',
        'optional_outer_url_prefix': prefix,
        'required_transport_protocol': protocol,
        'wrapper_url_prefix': url_prefix,
        'constructed_transport_rtti': transport_class,
        'derived_vtable': hex(vtable),
        'verified_instructions': [{'address': hex(a), 'mnemonic': m, 'operands': o} for a, m, o in checks],
        'unsupported_protocol_message': cstring(aa, 0x14ef34),
        'selected_networking_or_plugin_loader_imports': imports,
        'conclusion': 'Native Wireless Android Auto is not implemented by the shipped projection path; this is not an existing option to enable in configuration',
        'limits': ['No on-unit connection test', 'No determination of Wi-Fi chip/radio capabilities',
                   'No conclusion about other Cinemo builds or replacement/custom software'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receiver', type=Path, default=Path('analysis/second1/files/second1/MediaOne/cinemo/libNmeAndroidAuto.so'))
    parser.add_argument('--wrapper', type=Path, default=Path('analysis/second1/files/second1/lib/libGALSVC.so'))
    parser.add_argument('--output', type=Path, default=Path('analysis/wireless-audit/verification.json'))
    args = parser.parse_args()
    for source in (args.receiver, args.wrapper):
        separate_output(source.parent, args.output)
    result = verify(args.receiver, args.wrapper)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(result['conclusion'])


if __name__ == '__main__':
    main()
