"""Find candidate Thumb references formed by literal loads and PC-relative adds.

This is a local constant tracker, not a control-flow or reachability proof.
Inspect the referenced functions before drawing conclusions. Requires the
dependencies in requirements-firmware.txt; does not execute inspected code.
"""

import argparse
import json
from pathlib import Path

from capstone import CS_MODE_ARM
from capstone.arm import ARM_OP_REG, ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R12

from arm_inspect import ArmElf


def candidate_refs(elf, pattern):
    targets = {item['address']: item['text'] for item in elf.strings(pattern)}
    result = []
    ranges = list(zip(elf.functions, elf.functions[1:]))
    for start, end in ranges:
        values = {}
        for ins in elf.instructions(start, end):
            if not ins.id:
                values.clear()
                continue
            ops = ins.operands
            if not ops:
                continue
            pc = ins.address + (8 if elf.decoder.mode == CS_MODE_ARM else 4)
            def value(op):
                if op.type == ARM_OP_IMM:
                    return op.imm
                if op.type == ARM_OP_REG:
                    return pc if op.reg == ARM_REG_PC else values.get(op.reg)
                return None
            assigned = None
            dest = ops[0].reg if ops[0].type == ARM_OP_REG else None
            name = ins.mnemonic.split('.')[0]
            try:
                if name in ('mov', 'movs', 'movw') and len(ops) == 2:
                    assigned = value(ops[1])
                elif name == 'movt' and dest in values:
                    assigned = (values[dest] & 65535) | (ops[1].imm << 16)
                elif name in ('add', 'adds', 'sub', 'subs'):
                    left = values.get(dest) if len(ops) == 2 else value(ops[1])
                    right = value(ops[-1])
                    if left is not None and right is not None:
                        assigned = left - right if name.startswith('sub') else left + right
                elif name == 'adr':
                    assigned = (pc & ~3) + ops[1].imm
                elif name == 'ldr' and len(ops) == 2 and ops[1].type == ARM_OP_MEM:
                    mem = ops[1].mem
                    base = (pc & ~3) if mem.base == ARM_REG_PC else values.get(mem.base)
                    index = values.get(mem.index) if mem.index else 0
                    if base is not None and index is not None:
                        assigned = elf.u32((base + index + mem.disp) & 0xffffffff)
            except ValueError:
                pass
            _, written = ins.regs_access()
            for register in written:
                values.pop(register, None)
            if dest is not None and assigned is not None:
                assigned &= 0xffffffff
                values[dest] = assigned
                if assigned in targets:
                    result.append({'instruction': hex(ins.address), 'function': hex(start),
                                   'target': hex(assigned), 'text': targets[assigned]})
            if name in ('bl', 'blx'):
                for register in (ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R12):
                    values.pop(register, None)
    return {'strings': [{'address': hex(a), 'text': t} for a, t in targets.items()],
            'candidate_references': result,
            'limitation': 'Local constant tracking; control flow and reachability require manual review'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('pattern')
    parser.add_argument('--arm', action='store_true', help='Track ARM instructions instead of Thumb')
    args = parser.parse_args()
    print(json.dumps(candidate_refs(ArmElf(args.elf, arm=args.arm), args.pattern), indent=2))


if __name__ == '__main__':
    main()
