"""Behavioral tests of the proposed bridge policy, not vehicle validation."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from navigation_replay import Replay, preview_html, replay


class NavigationReplayTests(unittest.TestCase):
    def setUp(self):
        self.model = Replay(ttl=10)
        self.event('connect', at=0)
        self.event('start', at=0)

    def event(self, kind, at=1, source='android_auto', session='s1', route='r1', **kwargs):
        data = {'at': at, 'kind': kind}
        if kind not in ('tick', 'control'):
            data.update(source=source, session=session)
        if kind not in ('tick', 'control', 'connect', 'disconnect'):
            data['route'] = route
        data.update(kwargs)
        return self.model.step(data)['displays']['gauge_cluster']

    def turn(self, at=1, mid='m1', **kwargs):
        return self.event('turn', at=at, maneuver_id=mid, maneuver='left', **kwargs)

    def distance(self, at=2, mid='m1', meters=100, **kwargs):
        return self.event('distance', at=at, maneuver_id=mid, meters=meters, **kwargs)

    def test_new_turn_cannot_inherit_previous_distance(self):
        self.turn()
        self.assertEqual(self.distance()['distance_m'], 100)
        view = self.turn(at=3, mid='m2')
        self.assertTrue(view['visible'])
        self.assertIsNone(view['distance_m'])
        with self.assertRaises(ValueError):
            self.distance(at=4, mid='m1')

    def test_distance_updates_do_not_refresh_turn_lifetime(self):
        self.turn()
        self.distance(at=10)
        self.assertFalse(self.event('tick', at=11)['visible'])
        with self.assertRaises(ValueError):
            self.distance(at=12)

    def test_cancel_and_disconnect_clear_and_reject_delayed_events(self):
        for kind in ('cancel', 'disconnect'):
            with self.subTest(kind=kind):
                self.setUp()
                self.turn()
                self.assertFalse(self.event(kind, at=3)['visible'])
                with self.assertRaises(ValueError):
                    self.distance(at=4)

    def test_old_session_and_closed_route_cannot_be_reused(self):
        self.event('disconnect', at=1)
        with self.assertRaises(ValueError):
            self.event('connect', at=2)
        self.event('connect', at=2, session='s2')
        with self.assertRaises(ValueError):
            self.turn(at=3)
        self.event('start', at=3, session='s2')
        self.event('cancel', at=4, session='s2')
        with self.assertRaises(ValueError):
            self.event('start', at=5, session='s2')

    def test_native_guidance_priority_including_stale_native(self):
        self.turn()
        self.event('connect', at=2, source='native')
        view = self.event('start', at=2, source='native')
        self.assertEqual(view['owner'], 'native')
        self.assertFalse(view['visible'])
        self.turn(at=3, source='native')
        self.turn(at=12, mid='m2')
        view = self.event('tick', at=13)
        self.assertEqual(view['owner'], 'native')
        self.assertFalse(view['visible'])
        view = self.event('cancel', at=14, source='native')
        self.assertEqual(view['owner'], 'android_auto')
        self.assertTrue(view['visible'])

    def test_reenable_cannot_revive_disabled_guidance(self):
        self.turn()
        self.assertFalse(self.event('control', at=2, enabled=False)['visible'])
        with self.assertRaises(ValueError):
            self.turn(at=3, mid='m2')
        self.assertFalse(self.event('control', at=3, enabled=True)['visible'])
        with self.assertRaises(ValueError):
            self.event('start', at=4)
        self.event('start', at=4, route='r2')
        self.assertTrue(self.turn(at=5, route='r2')['visible'])

    def test_invalid_events_are_atomic(self):
        self.turn()
        for meters in (-1, True, float('nan'), float('inf'), '10'):
            state = deepcopy(self.model)
            with self.assertRaises(ValueError):
                self.distance(at=2, meters=meters)
            self.assertEqual(self.model.sources, state.sources)
            self.assertEqual(self.model.time, state.time)
        for bad in ({'at': 0, 'kind': 'tick'}, {'at': 2, 'kind': []},
                    {'at': 2, 'kind': 'tick', 'send_can': True}):
            with self.assertRaises(ValueError):
                self.model.step(bad)

    def test_html_treats_road_as_text(self):
        self.turn(road='</script><script>alert(1)</script>')
        document = preview_html([self.model.snapshot()])
        self.assertNotIn('</script><script>alert(1)', document)
        self.assertIn('\\u003c/script>', document)
        self.assertNotIn('innerHTML', document)

    def test_fixture_and_cli_never_overwrite_existing_preview(self):
        root = Path(__file__).resolve().parents[1]
        fixture = root / 'fixtures/navigation/synthetic-drive.jsonl'
        frames = replay([json.loads(line) for line in fixture.read_text().splitlines()])
        self.assertEqual(len(frames), 14)
        self.assertFalse(frames[-1]['displays']['upper_dashboard']['visible'])
        self.assertEqual(frames[3]['displays']['gauge_cluster']['distance_m'], 250)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'preview.html'
            output.write_text('keep this file')
            result = subprocess.run([sys.executable, str(root / 'tools/navigation_replay.py'),
                                     str(fixture), '--html', str(output)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), 'keep this file')


if __name__ == '__main__':
    unittest.main()
