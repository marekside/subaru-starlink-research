"""Offline semantic navigation replay. No QNX, USB, network, PPS or CAN output.

Inputs are our JSONL event format, not raw Android Auto or Subaru messages.
Only an explicit --html option creates a new local preview file.
"""

import argparse
from copy import deepcopy
from dataclasses import dataclass, field
import json
import math
from pathlib import Path


MANEUVERS = {'left', 'right', 'straight', 'uturn', 'roundabout', 'exit', 'arrive', 'unknown'}
FIELDS = {
    'tick': set(), 'control': {'enabled'}, 'connect': {'source', 'session'},
    'disconnect': {'source', 'session'}, 'start': {'source', 'session', 'route'},
    'cancel': {'source', 'session', 'route'},
    'turn': {'source', 'session', 'route', 'maneuver_id', 'maneuver', 'road'},
    'distance': {'source', 'session', 'route', 'maneuver_id', 'meters'},
}
REQUIRED = {kind: fields - {'road'} for kind, fields in FIELDS.items()}


def number(value, label):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f'{label} must be a finite nonnegative number')
    return value


def token(value, label):
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError(f'{label} must be a nonempty string of at most 256 characters')


@dataclass
class Source:
    session: str | None = None
    sessions_used: set = field(default_factory=set)
    route: str | None = None
    routes_used: set = field(default_factory=set)
    maneuvers_used: set = field(default_factory=set)
    turn: dict | None = None
    turn_at: float | None = None
    distance: float | None = None
    distance_at: float | None = None
    reason: str = 'inactive'

    def clear_route(self, reason):
        self.route = None
        self.maneuvers_used.clear()
        self.clear_turn(reason)

    def clear_turn(self, reason):
        self.turn = self.turn_at = self.distance = self.distance_at = None
        self.reason = reason


class Replay:
    def __init__(self, ttl=15):
        self.ttl = number(ttl, 'ttl')
        if not ttl:
            raise ValueError('ttl must be positive')
        self.time = 0
        self.enabled = True
        self.sources = {name: Source() for name in ('android_auto', 'native')}

    def step(self, event):
        # Apply transactionally: malformed/stale events leave the state and clock intact.
        trial = deepcopy(self)
        result = trial._step(event)
        self.__dict__.update(trial.__dict__)
        return result

    def _step(self, event):
        if not isinstance(event, dict):
            raise ValueError('event must be an object')
        kind = event.get('kind')
        if not isinstance(kind, str) or kind not in FIELDS:
            raise ValueError('unknown event kind')
        allowed = FIELDS[kind] | {'kind', 'at'}
        if set(event) - allowed or not (REQUIRED[kind] | {'at', 'kind'}) <= set(event):
            raise ValueError(f'incorrect fields for {kind}')
        now = number(event['at'], 'at')
        if now < self.time:
            raise ValueError('events must be in nondecreasing time order')
        self.time = now
        # Independent clocks: distance traffic cannot keep an old maneuver alive.
        for source in self.sources.values():
            if source.turn is not None and now - source.turn_at >= self.ttl:
                source.clear_turn('stale_turn')
            elif source.distance is not None and now - source.distance_at >= self.ttl:
                source.distance = source.distance_at = None

        if kind == 'control':
            if type(event['enabled']) is not bool:
                raise ValueError('enabled must be boolean')
            self.enabled = event['enabled']
            if not self.enabled:
                for source in self.sources.values():
                    source.clear_route('disabled')
        elif kind != 'tick':
            name = event['source']
            if not isinstance(name, str) or name not in self.sources:
                raise ValueError('source must be android_auto or native')
            source = self.sources[name]
            token(event['session'], 'session')
            if kind == 'connect':
                if event['session'] in source.sessions_used:
                    raise ValueError('session token has already been used')
                source.clear_route('connected_without_guidance')
                source.session = event['session']
                source.sessions_used.add(source.session)
                source.routes_used.clear()
            else:
                if source.session is None or event['session'] != source.session:
                    raise ValueError('event does not match the connected session')
                if kind == 'disconnect':
                    source.clear_route('disconnected')
                    source.session = None
                else:
                    if not self.enabled:
                        raise ValueError('guidance events rejected while disabled')
                    token(event['route'], 'route')
                    if kind == 'start':
                        if event['route'] in source.routes_used:
                            raise ValueError('route token has already been used in this session')
                        source.clear_route('waiting_for_turn')
                        source.route = event['route']
                        source.routes_used.add(source.route)
                    else:
                        if source.route is None or source.route != event['route']:
                            raise ValueError('event does not match active guidance')
                        if kind == 'cancel':
                            source.clear_route('cancelled')
                        else:
                            token(event['maneuver_id'], 'maneuver_id')
                            if kind == 'turn':
                                if event['maneuver_id'] in source.maneuvers_used:
                                    raise ValueError('maneuver token has already been used in this route')
                                maneuver = event['maneuver']
                                if not isinstance(maneuver, str) or maneuver not in MANEUVERS:
                                    raise ValueError('unsupported semantic maneuver')
                                road = event.get('road', '')
                                if not isinstance(road, str) or len(road) > 256:
                                    raise ValueError('road must be a string of at most 256 characters')
                                source.clear_turn('guidance')
                                source.turn = {'id': event['maneuver_id'], 'maneuver': maneuver, 'road': road}
                                source.turn_at = now
                                source.maneuvers_used.add(event['maneuver_id'])
                            elif kind == 'distance':
                                if source.turn is None or event['maneuver_id'] != source.turn['id']:
                                    raise ValueError('distance does not match a fresh maneuver')
                                source.distance = number(event['meters'], 'meters')
                                source.distance_at = now
        return self.snapshot()

    def snapshot(self):
        # Proposed conservative policy, not a claim about Subaru's arbitration.
        owner = next((n for n in ('native', 'android_auto') if self.sources[n].route is not None), None)
        source = self.sources[owner] if owner else None
        view = {'visible': bool(self.enabled and source and source.turn),
                'owner': owner, 'maneuver': None, 'distance_m': None, 'road': '',
                'reason': 'disabled' if not self.enabled else source.reason if source else 'no_guidance',
                'native_encoding': 'unresolved', 'hardware_validated': False}
        if view['visible']:
            view.update(maneuver=source.turn['maneuver'], road=source.turn['road'], distance_m=source.distance)
        return {'at': self.time, 'mode': 'offline_semantic_preview',
                'displays': {name: dict(view) for name in ('upper_dashboard', 'gauge_cluster')}}


def replay(events, ttl=15):
    model = Replay(ttl)
    return [model.step(event) for event in events]


def preview_html(snapshots):
    # Escape '<' so user-controlled road labels cannot terminate the JSON script tag.
    payload = json.dumps(snapshots, ensure_ascii=True, allow_nan=False).replace('<', '\\u003c')
    return '''<!doctype html><html lang="en"><meta charset="utf-8">
<title>Offline navigation replay</title>
<style>body{font:18px system-ui;background:#111820;color:#eee;max-width:900px;margin:40px auto;padding:16px}
article{border:1px solid #607080;border-radius:12px;padding:20px;margin:18px 0}input{width:100%}
strong{font-size:30px}small{color:#bcc8d0}</style>
<h1>Offline navigation replay</h1>
<p>Semantic mock displays. Native codes, actual layout and hardware behavior are unvalidated.</p>
<input id="frame" aria-label="Replay frame" type="range" min="0" value="0"><p id="time"></p>
<article><h2>Upper dashboard</h2><strong id="upper"></strong><p id="upperdetail"></p></article>
<article><h2>Gauge cluster</h2><strong id="gauge"></strong><p id="gaugedetail"></p></article>
<small>Local preview only. No vehicle connection or transmit controls.</small>
<script type="application/json" id="data">''' + payload + '''</script>
<script>
const frames=JSON.parse(document.getElementById('data').textContent);
const slider=document.getElementById('frame');slider.max=Math.max(0,frames.length-1);
const arrows={left:'←',right:'→',straight:'↑',uturn:'↶',roundabout:'⟳',exit:'↗',arrive:'⚑',unknown:'?'};
function draw(){const f=frames[+slider.value];if(!f)return;
document.getElementById('time').textContent=`Frame ${+slider.value+1}/${frames.length} · ${f.at} seconds`;
for(const [key,id] of [['upper_dashboard','upper'],['gauge_cluster','gauge']]){
const v=f.displays[key];document.getElementById(id).textContent=v.visible?`${arrows[v.maneuver]} ${v.distance_m===null?'—':v.distance_m+' m'}`:'—';
document.getElementById(id+'detail').textContent=[v.owner||'no source',v.reason,v.road].filter(Boolean).join(' · ');
}}slider.addEventListener('input',draw);draw();</script></html>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('events', type=Path, help='Normalized JSONL events, not a raw unit log')
    parser.add_argument('--ttl', type=float, default=15, help='Illustrative expiry in seconds (default 15)')
    parser.add_argument('--html', type=Path, help='Create a new standalone .html preview; never overwrite')
    args = parser.parse_args()
    try:
        events = []
        for line_no, line in enumerate(args.events.read_text(encoding='utf-8-sig').splitlines(), 1):
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f'line {line_no}: {exc}') from exc
        model, snapshots = Replay(args.ttl), []
        for index, event in enumerate(events, 1):
            try:
                snapshots.append(model.step(event))
            except ValueError as exc:
                raise ValueError(f'event {index}: {exc}') from exc
        if args.html:
            if args.html.suffix.lower() != '.html':
                raise ValueError('preview must have an .html extension')
            with args.html.open('x', encoding='utf-8') as stream:
                stream.write(preview_html(snapshots))
        for snapshot in snapshots:
            print(json.dumps(snapshot, allow_nan=False))
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Replay failed: {exc}\n')


if __name__ == '__main__':
    main()
