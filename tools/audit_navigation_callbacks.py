"""Read-only, build-specific navigation callback audit; never executes firmware.

Requires the same analysis dependencies as arm_inspect.py. Prints JSON to stdout.
Instruction addresses apply only to the hash-pinned stock binaries below.
"""

import argparse
import hashlib
import json
from pathlib import Path

from arm_inspect import ArmElf


BINARIES = {
    'receiver': ('analysis/second1/files/second1/MediaOne/cinemo/libNmeAndroidAuto.so',
                 '32f5e8847c033a283bbfcc6b465d08b5ab6a4ee0a2d92b6cb51369346dae8a97'),
    'wrapper': ('analysis/second1/files/second1/lib/libGALSVC.so',
                '49b8f393b866773520f22c0e64e98d5c8df4bfc6e291ee70cfa2c71872dc8dde'),
    'display': ('analysis/second1/files/second1/bin/MFDService',
                '4fd028f843a8747be8c5f37c0d493ed0f80eb1c96eeac2b3d8f789c63a58fb04'),
    'producer': ('analysis/navifs/files/nav/OpenNav/SubaruOpenNavController',
                 '011493bc779c16b6689ef84141b616c976bbf75ac5aacab9985b334da82f5869'),
}


def audit(root, analysis_root=None):
    analysis_root = analysis_root if analysis_root is not None else root / 'analysis'
    images, hashes = {}, {}
    for name, (relative, expected) in BINARIES.items():
        elf = ArmElf(analysis_root / Path(relative).relative_to('analysis'), arm=name == 'receiver')
        digest = hashlib.sha256(elf.data).hexdigest()
        if digest != expected:
            raise ValueError(f'{name}: unsupported stock binary hash')
        images[name], hashes[name] = elf, digest
    receiver, wrapper, display = (images[n] for n in ('receiver', 'wrapper', 'display'))

    def instruction(elf, address, mnemonic, operands):
        ins = next(elf.instructions(address, address + 4))
        if (ins.mnemonic, ins.op_str) != (mnemonic, operands):
            raise ValueError(f'Unexpected instruction at {address:#x}')

    # Public vtable's +0x18 slot forwards the table unchanged to the internal copy.
    if receiver.u32(0x180138 + 0x18) != 0x20f8c:
        raise ValueError('Unexpected receiver SetCallbacks vtable slot')
    instruction(receiver, 0x21068, 'add', 'r0, r8, #0x38')
    instruction(receiver, 0x2106c, 'mov', 'r1, sl')
    instruction(receiver, 0x21070, 'mov', 'r2, sb')
    instruction(receiver, 0x21074, 'bl', '#0x26354')
    instruction(receiver, 0x26498, 'add', 'r0, r5, #0x1300')
    instruction(receiver, 0x264a0, 'add', 'r0, r0, #4')
    instruction(receiver, 0x264a8, 'mov', 'r2, #0x9c')
    if receiver.import_name(0x175f8) != 'memcpy':
        raise ValueError('Unexpected callback copy import')
    instruction(receiver, 0x264ac, 'bl', '#0x175f8')

    # Wrapper zeroes the whole table and fills these exact stack slots.
    instruction(wrapper, 0x16a38, 'movs', 'r1, #0')
    instruction(wrapper, 0x16a3a, 'movs', 'r2, #0x9c')
    instruction(wrapper, 0x16a3c, 'add', 'r0, sp, #8')
    if wrapper.import_name(0x131f4) != 'memset':
        raise ValueError('Unexpected wrapper table initialization import')
    instruction(wrapper, 0x16a3e, 'blx', '#0x131f4')
    instruction(wrapper, 0x16a98, 'ldr', 'r3, [r3, #0x18]')
    got = (0x16a2c + wrapper.u32(0x16ad8)) & 0xffffffff
    initialized = {}
    # (literal address, callback offset, store instruction, stack displacement)
    locations = [
        (0x16ae4, 0x00, 0x16a4c, 0x08), (0x16ae8, 0x04, 0x16a52, 0x0c),
        (0x16aec, 0x08, 0x16a58, 0x10), (0x16af0, 0x10, 0x16a5e, 0x18),
        (0x16af4, 0x14, 0x16a64, 0x1c), (0x16af8, 0x18, 0x16a6a, 0x20),
        (0x16afc, 0x1c, 0x16a70, 0x24), (0x16b00, 0x24, 0x16a76, 0x2c),
        (0x16b04, 0x28, 0x16a7c, 0x30), (0x16b08, 0x2c, 0x16a82, 0x34),
        (0x16b0c, 0x30, 0x16a88, 0x38), (0x16b10, 0x48, 0x16a8e, 0x50),
        (0x16b14, 0x44, 0x16a94, 0x4c),
    ]
    for literal, offset, store, displacement in locations:
        disp = str(displacement) if displacement < 10 else hex(displacement)
        instruction(wrapper, store, 'str', f'r3, [sp, #{disp}]')
        slot = (got + wrapper.u32(literal)) & 0xffffffff
        initialized[hex(offset)] = wrapper.relocations[slot]

    callbacks = {}
    for name, offset, object_offset, address in [
        ('status', 0x4c, 0x1350, 0x3fbc8),
        ('next_turn', 0x50, 0x1354, 0x3fd58),
        ('next_turn_distance', 0x54, 0x1358, 0x3fed4),
    ]:
        instruction(receiver, address, 'movw', f'{"r0" if name == "next_turn_distance" else "r3"}, #{object_offset:#x}')
        callbacks[name] = {'table_offset': hex(offset), 'internal_offset': hex(object_offset),
                           'wrapper_value_at_registration': 0}
    for address, offset in [(0x2752c, 0x1314), (0x2753c, 0x1354),
                            (0x2754c, 0x1358), (0x2755c, 0x1350)]:
        instruction(receiver, address, 'movw', f'r3, #{offset:#x}')

    # Metadata names resolved via GOT relocations, rather than guessed from labels.
    receiver_got = 0x274d8 + receiver.u32(0x27bdc)
    metadata = [receiver.relocations[receiver_got + off]
                for off in (0xbec, 0x824, 0x5e0, 0x6bc, 0x948)]
    # Values supplied by the wrapper's Android Auto setup path, not config guesses.
    instruction(wrapper, 0x1af62, 'mov.w', 'r3, #0x3e8')
    instruction(wrapper, 0x1af66, 'str', 'r3, [sp, #0x68]')
    instruction(wrapper, 0x1af68, 'movs', 'r3, #0')
    for address, offset in [(0x1af6a, 0x6c), (0x1af6c, 0x70), (0x1af70, 0x74)]:
        instruction(wrapper, address, 'str', f'r3, [sp, #{offset:#x}]')
    instruction(wrapper, 0x1af72, 'movs', 'r3, #2')
    instruction(wrapper, 0x1af74, 'str', 'r3, [sp, #0x78]')
    configured = {}
    for address, stack_offset, value in [(0x1b7ca, 0x68, 1000), (0x1b7ee, 0x6c, 0),
                                         (0x1b812, 0x70, 0), (0x1b836, 0x74, 0),
                                         (0x1b85a, 0x78, 2)]:
        ins = next(wrapper.instructions(address, address + 4))
        literal = ((address + 4) & ~3) + ins.operands[1].mem.disp
        name = wrapper.relocations[got + wrapper.u32(literal)]
        instruction(wrapper, address + 4, 'add', f'r4, sp, #{stack_offset:#x}')
        configured[name] = value
    instruction(wrapper, 0x1bbe4, 'blx', '#0x12d78')
    if 'GALSvcCinemoIntSetCinemoCallback' not in wrapper.import_name(0x12d78):
        raise ValueError('Unexpected setup callback registration caller')
    instruction(display, 0x8063cd2, 'blx', '#0x805095c')
    if display.import_name(0x805095c) != '_ZNK4Json5Value5isIntEv':
        raise ValueError('Unexpected native JSON field type check')

    def literal_string(address, elf=display):
        ins = next(elf.instructions(address, address + 4))
        target = elf.u32(((address + 4) & ~3) + ins.operands[1].mem.disp)
        return elf.read(target, 100).split(b'\0', 1)[0].decode('ascii')

    contracts = {}
    for signal, locations in {
        'navClusterNextTurnInfo': [(0x8063ea6, 0x8063eae), (0x8063ebc, 0x8063ec4),
                                   (0x8063ed6, 0x8063ede), (0x8063eec, 0x8063ef8),
                                   (0x8063f06, 0x8063f0e)],
        'navClusterNavigationStatus': [(0x80640ce, 0x80640d6), (0x80640e4, 0x80640ec),
                                       (0x80640fe, 0x8064106)],
        'navClusterNextDestinationInfo': [(0x8064816, 0x806481e), (0x806482c, 0x8064834),
                                          (0x8064846, 0x806484e)],
    }.items():
        contracts[signal] = {literal_string(a): literal_string(b).removesuffix('::')
                             for a, b in locations}
    producer_formats = {
        'navClusterNextTurnInfo': literal_string(0x81163d4, images['producer']),
        'navClusterNextDestinationInfo': literal_string(0x8116350, images['producer']),
    }
    if producer_formats['navClusterNextTurnInfo'] != '{"interruptFlag":%d,"category":%d,"rotaryAvailable":%d,"segment":%d,"turnIcon":%d}':
        raise ValueError('Unexpected native next-turn producer format')
    return {
        'status': 'Static evidence verified for hash-pinned stock build; no runtime validation',
        'sha256': hashes,
        'callback_table_bytes': 156, 'wrapper_function': '0x16a1c',
        'receiver_public_vtable': '0x180138', 'receiver_set_callbacks': '0x20f8c',
        'receiver_internal_table_copy': '0x26494..0x264ac',
        'initialized_wrapper_callbacks': initialized, 'navigation_callbacks': callbacks,
        'endpoint_gate': '0x2752c..0x27568', 'navigation_metadata': metadata,
        'wrapper_setup_function': '0x1ab78', 'wrapper_registration_call': '0x1bbe4',
        'wrapper_navigation_metadata_values': configured,
        'native_integer_field_mappings': contracts,
        'native_producer_formats': producer_formats,
        'native_integer_parser': '0x8063c7c; skips absent/non-isInt fields; accepts partial recognized fields',
        'conclusion': 'This wrapper registration leaves all three navigation data callbacks null; '
                      'the receiver registration gate rejects that table.',
        'limits': ['Not an exhaustive proof against another registration path or later mutation',
                   'Callback offsets/calling shapes are not a complete source-level SDK header',
                   'No display enum meanings, distance scaling or per-display routing validated'],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--analysis-root', type=Path, help='Alternate extracted analysis tree; binary hash checks still apply')
    args = parser.parse_args()
    try:
        print(json.dumps(audit(args.root, args.analysis_root), indent=2))
    except (ValueError, OSError, KeyError, StopIteration) as exc:
        parser.exit(1, f'Audit failed: {exc}\n')
