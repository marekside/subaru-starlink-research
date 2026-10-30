"""Optional binary-backed tests: require local extracted stock image and deps."""

import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECEIVER = ROOT / 'analysis/rel-a2.25.15.20/second1/files/second1/MediaOne/cinemo/libNmeAndroidAuto.so'
AVAILABLE = RECEIVER.is_file() and all(importlib.util.find_spec(x) for x in ('unicorn', 'capstone', 'elftools'))
sys.path.insert(0, str(ROOT / 'tools'))


@unittest.skipUnless(AVAILABLE, 'Requires local extracted matching receiver and analysis dependencies')
class CallbackProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from probe_navigation_callbacks import CallbackProbe
        cls.probe = CallbackProbe(RECEIVER)

    def test_status_accepts_only_three_observed_values(self):
        for status in (0, 1, 2):
            self.assertEqual(self.probe.run('status', [status, 0, 0]), [[self.probe.CONTEXT, status]])
        for status in (3, 0xffffffff):
            self.assertEqual(self.probe.run('status', [status, 0, 0]), [])

    def test_distance_preserves_three_words_and_defaults_unknown_units(self):
        for unit in range(10):
            expected = unit if unit <= 7 else 0
            self.assertEqual(self.probe.run('distance', [123, 456, 789], [unit]),
                             [[self.probe.CONTEXT, 123, 456, 789, expected]])

    def test_next_turn_translation_and_string_blob_forwarding(self):
        for code in range(21):
            expected = code if 1 <= code <= 19 and code not in (15, 18) else 0
            words = self.probe.next_turn(1, code)[0]
            self.assertEqual(words, [self.probe.CONTEXT, self.probe.INPUT + 0x100,
                                     1, expected, self.probe.INPUT + 0x200, 3, 0x55, 0x66])
        for side, expected in [(0, 3), (1, 1), (2, 2), (3, 3)]:
            self.assertEqual(self.probe.next_turn(side, 1)[0][2], expected)

    def test_null_callbacks_do_not_dispatch(self):
        self.assertEqual(self.probe.run('status', [1, 0, 0], registered=False), [])
        self.assertEqual(self.probe.next_turn(1, 1, registered=False), [])
        self.assertEqual(self.probe.run('distance', [1, 2, 3], [1], registered=False), [])


if __name__ == '__main__':
    unittest.main()
