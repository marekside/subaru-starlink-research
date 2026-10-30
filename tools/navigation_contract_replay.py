"""Inspect normalized native navigation JSONL offline; never transmits messages.

This is not a raw unit-log decoder or semantic turn-to-native encoder. Numeric
codes are kept uninterpreted. Inputs must be explicitly normalized by an analyst.
The strict integer input schema is narrower than a full JSONCpp emulation.
"""

import argparse
import json
from pathlib import Path

from navigation_replay import number


def inspect(records, origin='synthetic', interfaces=None):
    if origin not in ('synthetic', 'normalized_capture'):
        raise ValueError('unknown evidence origin')
    if interfaces is None:
        path = Path(__file__).resolve().parents[1] / 'doc/android-auto-display-interfaces.json'
        interfaces = json.loads(path.read_text(encoding='utf-8'))
    contracts = {name: data['observed_field_to_pps_attribute']
                 for name, data in interfaces['native_navigation']['signals'].items()
                 if 'observed_field_to_pps_attribute' in data}
    updates, state, observed = [], {}, {}
    previous = 0
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict) or set(record) != {'at', 'signal', 'payload'}:
            raise ValueError(f'record {index}: expected at, signal and payload')
        at = number(record['at'], 'at')
        if at < previous:
            raise ValueError(f'record {index}: timestamps out of order')
        signal, payload = record['signal'], record['payload']
        if not isinstance(signal, str) or signal not in contracts or not isinstance(payload, dict):
            raise ValueError(f'record {index}: unsupported signal/payload')
        mapping = contracts[signal]
        accepted, ignored = {}, []
        for name, value in payload.items():
            if name not in mapping:
                ignored.append(name)
                continue
            if type(value) is not int or not -(2**31) <= value < 2**31:
                raise ValueError(f'record {index}: {name} must be a signed 32-bit integer in this input schema')
            accepted[mapping[name]] = value
            observed.setdefault(signal, {}).setdefault(name, set()).add(value)
        if not accepted:
            raise ValueError(f'record {index}: no recognized integer fields')
        # Preserve partial raw updates; do not infer enum meaning or clearing.
        state.setdefault(signal, {}).update(accepted)
        updates.append({'at': at, 'signal': signal, 'attribute_values': accepted,
                        'ignored_fields': sorted(ignored),
                        'missing_fields': sorted(mapping.keys() - payload.keys())})
        previous = at
    return {'mode': 'offline_native_contract_inspection', 'origin': origin,
            'origin_verified': False, 'hardware_validated': False,
            'display_routing': 'unresolved', 'native_enum_meanings': 'unresolved',
            'updates': updates, 'last_raw_state_by_signal': state,
            'observed_values': {s: {f: sorted(v) for f, v in fields.items()} for s, fields in observed.items()},
            'limits': ['No raw log decoding, semantic conversion, PPS encoding or vehicle output',
                       'origin is analyst-supplied, not proof of a real capture',
                       'destination distance and next-maneuver distance are not interchangeable',
                       'Raw state is an observation history, not a display state or freshness policy']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('records', type=Path)
    parser.add_argument('--origin', choices=['synthetic', 'normalized_capture'], default='synthetic')
    args = parser.parse_args()
    try:
        records = [json.loads(line) for line in args.records.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
        print(json.dumps(inspect(records, args.origin), indent=2, allow_nan=False))
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Contract replay failed: {exc}\n')
