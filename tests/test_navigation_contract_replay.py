import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from navigation_contract_replay import inspect


class NativeContractTests(unittest.TestCase):
    def record(self, at=0, payload=None):
        return {'at': at, 'signal': 'navClusterNextTurnInfo',
                'payload': {'turnIcon': 91} if payload is None else payload}

    def test_partial_updates_preserve_raw_fields_without_enum_labels(self):
        result = inspect([self.record(payload={'turnIcon': 91, 'category': 7}),
                          self.record(at=1, payload={'turnIcon': 92})])
        state = result['last_raw_state_by_signal']['navClusterNextTurnInfo']
        self.assertEqual(state['AVN6B3_3_0_TBT_DIRECTION'], 92)
        self.assertEqual(state['AVN6B3_2_4_TBT_CATEGORY'], 7)
        self.assertEqual(result['observed_values']['navClusterNextTurnInfo']['turnIcon'], [91, 92])
        self.assertEqual(result['native_enum_meanings'], 'unresolved')
        self.assertEqual(result['display_routing'], 'unresolved')
        self.assertFalse(result['origin_verified'])

    def test_strict_input_rejects_booleans_floats_and_out_of_range(self):
        for value in [True, 1.0, '1', -(2**31)-1, 2**31]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                inspect([self.record(payload={'turnIcon': value})])
        for value in [-(2**31), 2**31-1]:
            inspect([self.record(payload={'turnIcon': value})])

    def test_unknown_fields_are_not_encoded_and_empty_update_rejected(self):
        result = inspect([self.record(payload={'turnIcon': 91, 'roadName': 'text'})])
        self.assertEqual(result['updates'][0]['ignored_fields'], ['roadName'])
        with self.assertRaises(ValueError):
            inspect([self.record(payload={'roadName': 'text'})])

    def test_capture_label_cannot_claim_hardware_validation(self):
        result = inspect([self.record()], origin='normalized_capture')
        self.assertFalse(result['origin_verified'])
        self.assertFalse(result['hardware_validated'])
        with self.assertRaises(ValueError):
            inspect([self.record(at=1), self.record(at=0)])

    def test_fixture_keeps_destination_distance_unencoded(self):
        fixture = Path(__file__).resolve().parents[1] / 'fixtures/navigation/native-contract-synthetic.jsonl'
        result = inspect([json.loads(line) for line in fixture.read_text().splitlines()])
        self.assertEqual(result['updates'][-1]['ignored_fields'], ['distance', 'second'])
        self.assertEqual(len(result['updates']), 4)


if __name__ == '__main__':
    unittest.main()
