# T03–T05: navigation bridge investigation and offline prototype

Started against the supplied EU High `Rel_A2.24.41.20` build. All work described
here is offline. No firmware was repacked, installed or executed as a QNX process.

The matching **`Rel_A2.25.15.20`** package has since been supplied and compared.
Its receiver, wrapper, display service and HMI are byte-identical, and the
callback audit also passes against that extraction. The static findings below
therefore apply to both packages. The semantic prototype is independent of
either firmware version. See [comparison](firmware-version-comparison.md);
runtime observation and recovery remain outstanding.

## T03: callback registration traced further

The reviewed Subaru wrapper registration leaves all three navigation data
callbacks null. The receiver's navigation-endpoint gate rejects that table.
This is stronger than the earlier string evidence, but does not exclude another
registration path or later callback-table mutation elsewhere in the software.

Reproduce the hash-pinned audit from the repository root in PowerShell:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'analysis/python-deps')
python tools/audit_navigation_callbacks.py
```

The script requires the existing firmware analysis dependencies. It reads the
extracted binaries and prints evidence as JSON. Unknown binary hashes fail closed.

The chain is:

1. `libGALSVC.so`, `0x16a1c`, initializes a 156-byte callback table to zero.
   It installs session, focus, video, audio, Bluetooth and media callbacks and
   calls the Android Auto object's vtable slot `+0x18`.
2. The receiver's vtable at `0x180138` has `0x20f8c` in that slot. This method
   forwards context and the table to `0x26354`, adjusting its internal object
   pointer by `0x38`. At `0x26494..0x264ac`, context is stored at internal
   `+0x1300` and the table is copied unchanged to `+0x1304` using `memcpy`.
3. `ThreadRegisterNavigation`, `0x274b8`, checks four nonnull pointers at
   `0x2752c..0x27568`. A missing pointer branches to the skip path at `0x27654`.

| Callback | Offset in supplied callback table | Offset in internal receiver object | Reviewed wrapper assignment |
| --- | --- | --- | --- |
| Navigation focus request | `0x10` | `0x1314` | Installed |
| Navigation status | `0x4c` | `0x1350` | Zero |
| Next turn | `0x50` | `0x1354` | Zero |
| Next-turn distance | `0x54` | `0x1358` | Zero |

Navigation focus is distinct from navigation data. The wrapper's media metadata
and playback status slots at `0x44` and `0x48` are not the missing navigation
slots. The `GetNavData` setting concerns vehicle sensor data sent to the phone;
it does not fill these callback slots.

Endpoint registration also reads metadata identified through GOT relocations:
`NMEMETANAME_ANDROIDAUTO_NAVIGATION_MININTERVAL`, `..._TYPE`, `..._HEIGHT`,
`..._WIDTH` and `..._COLORDEPTH`. Code at `0x27798..0x277a8` accepts type values
1 and 2; type 1 additionally requires nonzero dimensions and color depth at
`0x27958..0x27978`. Do not assign undocumented SDK enum names to these values.
The subsequent pass resolved the reviewed wrapper's configured values and
setup caller, as described below. Other registration paths remain unexcluded.

### Endpoint setup and bounded dispatch probes

The setup function `GALSvcCinemoIntAndroidAuto` at `0x1ab78` constructs the
metapool settings before calling the reviewed callback-registration method via
its PLT at `0x1bbe4`. Its local values at `0x1af62..0x1af74` are submitted to
the navigation metadata keys at `0x1b7ca..0x1b87c`:

| Setting | Supplied value | Static interpretation |
| --- | --- | --- |
| Navigation minimum interval | 1000 | Native SDK value; physical time unit not established by this pass |
| Navigation height | 0 | No requested image height |
| Navigation width | 0 | No requested image width |
| Navigation color depth | 0 | No requested image color depth |
| Navigation type | 2 | Accepted by receiver gate; friendly SDK enum name remains unverified |

These are code-derived values, not suggested configuration edits. Type 2 takes
the path that does not require nonzero image dimensions. The earlier callback
gate still skips registration because the three data slots are null. No
additional direct/PLT caller of the reviewed registration was found in the
wrapper's scanned function ranges; indirect calls, other libraries and later
mutations are not excluded by that bounded search.

`tools/probe_navigation_callbacks.py` now executes only the three hash-pinned
dispatch functions under Unicorn with synthetic inputs. Original firmware pages
are read-only. A dummy logging-level read returns a value that skips logging,
and a dummy callback records argument words. Unexpected code destinations or
interrupts fail closed; each invocation has time/instruction limits. No QNX
system calls, startup code, devices or real phone messages are involved.

Observed results, also covered by binary-backed tests:

- Status 0, 1 and 2 forward context and the unchanged status word; 3 and
  `0xffffffff` do not dispatch. Meanings of the status values remain unresolved.
- Distance forwards context plus three unchanged argument words and the unit
  enum: values 0–7 are preserved; tested unknown units 8 and 9 become 0.
  The words have not been proven to represent any particular physical units.
- Next turn forwards eight words: context, road-data pointer, translated enum A,
  translated enum B, blob-data pointer, blob byte length and two trailing words.
  Enum A maps 1 to 1, 2 to 2 and tested 0/3 to 3. Enum B preserves 1–19 except
  15 and 18, which map to 0; tested 0/20 also map to 0. No Subaru icon meanings
  can be inferred from these receiver enum numbers.
- All three dispatch functions skip the callback when its slot is null.

These probes establish argument-word behavior for isolated stock code. They do
not establish source-level types, threading, lifetime rules or successful
Android Auto service discovery on the unit. The earlier partial calling-shape
description below remains intentionally untyped.

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'analysis/python-deps')
python tools/audit_navigation_callbacks.py --analysis-root analysis/rel-a2.25.15.20
python tools/probe_navigation_callbacks.py
```

Local results are under `analysis/rel-a2.25.15.20/navigation-deep/`.

The dispatch routines at `0x3fb68`, `0x3fce4` and `0x3fe70` read the three
navigation slots. Status accepts values 0, 1 and 2, forwarding the context plus
status. Next turn translates enums and forwards string/image-related data and
additional words. Distance forwards three incoming argument words and a mapped
unit value (0–7, unknown values default to 0). These are partial calling-shape
observations, not complete C/C++ declarations: parameter semantics, ownership,
lifetime, threading and all enum meanings remain unresolved. No SDK-compatible
callback implementation or patch is provided.

A companion that only listens to an existing service cannot create callbacks
that were never registered. If these slots remain null in the active path,
integration would need receiver/wrapper changes or a different data source.
That deployment question remains subject to T02 recovery requirements.

## T04: static contracts and observation plan

The audit also extracts the integer-field mappings directly from `MFDService`.
The existing [interface index](android-auto-display-interfaces.json) retains the
addresses and identifiers. New confirmations:

- The shared parser at `0x8063c7c` checks membership and `Json::Value::isInt`, then
  uses `asInt`. Absent or non-integer fields are skipped; at least one accepted
  field can make a partial update succeed. Do not substitute JSON booleans merely
  because a field has a flag-like name.
- `navClusterNextDestinationInfo` maps `units`, `digitPoint` and `etaChangeFlag`
  to `AVN6B2_2_0_DIST_UNIT`, `AVN6B2_2_3_DIST_DIGIT_POINT` and
  `AVN6B2_7_0_ARRIVAL_TIME_UPDATED`. Its other parser at `0x80635bc` decomposes
  distance/time values into multiple attributes. This has not been validated as
  an Android Auto next-maneuver-distance destination. Destination distance and
  next-turn distance must remain distinct.
- Turn/status handlers use the PPS writer at `0x806dde0`. Road and lane handlers
  registered at `0x8064bc8` and `0x8065120` also use separate IOC IPC interfaces.
  The existence of both paths does not establish which carries each field to
  each installed screen.

The owner reports that TomTom instructions appear on both screens. There are no
captured stock messages yet, so neither screen's full contract is validated.

The producer side is now traced too: `SubaruOpenNavController` at `0x81163a4`
formats the next-turn object with five signed decimal fields in this order:
`interruptFlag`, `category`, `rotaryAvailable`, `segment`, `turnIcon`, then
publishes `navClusterNextTurnInfo`. The updater/publisher at `0x8116b14` uses
the cached value when an input argument is `-1`. This sentinel belongs to that
producer routine; it is not proof that a JSON field containing `-1` means
"keep previous" to `MFDService`.

The destination publisher at `0x8116320` separately formats `units`, `distance`,
`second`, `etaChangeFlag` and `digitPoint`. The expanded hash-pinned audit
verifies both format strings against the extracted producer binary. This adds
producer/consumer agreement on field names, not validated enum meanings,
distance scaling or proof that both screens consume an identical contract.

| Observation | Record for upper display and gauge display separately | Question resolved |
| --- | --- | --- |
| Guidance start, cancel and arrival | Timestamp, displayed state, associated messages if available | Activation, clearing and ownership |
| Left, right and straight instructions | Displayed symbol and raw field values | Turn enum mapping |
| Roundabout and exit, if observed during ordinary use | Symbol, exit number and segment/lane fields | Rich maneuver encoding |
| Distances around unit/decimal transitions | Displayed number/unit, raw distance and digitPoint | Scaling, rounding and units |
| Phone disconnect or projection loss | Last valid instruction, clearing delay and messages | Expiry/reset behavior |
| Native guidance and Android Auto active together | Which source each screen shows and when it changes | Arbitration |

USB analytics exports may not contain the needed messages. Inspect them first.
The owner has since confirmed that the analytics export entry is absent from
the special menu; no capture is available. Another actually exposed stock export
or observation route must be established first. The owner has only the installed
unit, so bench-dependent access and recovery checks cannot currently be performed.
If authenticated read-only live observation is later established on bench
hardware, correlate the navigation service messages, PPS output and IOC IPC
activity; do not inject frames to discover enum meanings. Normal road observations
should be recorded by a passenger or collected afterward, not by operating
diagnostic menus while driving.

## T05: runnable semantic replay prototype

The prototype implements our own normalized event model. It does not emulate
QNX, decode a raw analytics archive, consume the stock callback ABI, encode native
messages, or communicate with the car. Both screen previews show the same
semantic intention with separate view objects; their layout and behavior are
mockups, not reproduced Subaru display contracts.

Run with the Python standard library only:

```powershell
python tools/navigation_replay.py fixtures/navigation/synthetic-drive.jsonl
python tools/navigation_replay.py fixtures/navigation/synthetic-drive.jsonl --html analysis/navigation-audit/preview-new.html
python -m unittest discover -s tests -v
```

The optional preview is a standalone HTML file with a frame slider. It is created
exclusively: an existing file is never overwritten. JSON snapshots go to stdout.
An example generated locally is `analysis/navigation-audit/preview.html`.

Inputs are one JSON object per line. `at` is a nondecreasing, finite, nonnegative
timestamp in seconds, relative to the test start. Event kinds:

| Kind | Fields in addition to `at` and `kind` |
| --- | --- |
| `connect`, `disconnect` | `source`, `session` |
| `start`, `cancel` | `source`, `session`, `route` |
| `turn` | `source`, `session`, `route`, `maneuver_id`, `maneuver`, optional `road` |
| `distance` | `source`, `session`, `route`, `maneuver_id`, `meters` |
| `tick` | None; advances time and applies expiry |
| `control` | Boolean `enabled` |

Sources are `android_auto` and `native`. Maneuvers are semantic names: `left`,
`right`, `straight`, `uturn`, `roundabout`, `exit`, `arrive`, `unknown`.
They are not Android Auto or Subaru numeric enum values. `meters` is normalized
distance to the current maneuver, not remaining journey distance. Capture
adapters will need to establish real source units before generating these events.

The adapter must provide unique session tokens, unique route tokens per session,
and unique maneuver tokens per route. Each turn event is a new maneuver, not a
heartbeat. Repeated SDK callbacks for the same maneuver will need normalization
in a future adapter. Delayed events from old sessions, routes or maneuvers are
rejected rather than silently reviving old guidance.

Proposed policy, not observed Subaru behavior:

- Native guidance retains ownership while active, even when its turn data is
  missing/stale; Android Auto does not silently take over. Cancellation or
  disconnect releases ownership, allowing fresh Android Auto guidance to show.
- A new maneuver clears the previous distance. Distance events must identify
  the current maneuver and cannot extend its lifetime.
- Turn and distance freshness have independent clocks. A tick models elapsed
  time when no messages arrive; replay does not run a background wall clock.
  The default 15-second expiry is illustrative, not calibrated to stock timing.
- Cancellation, disconnect and disable clear guidance. Re-enable requires new
  guidance and cannot revive the old route. Invalid events leave state and time
  unchanged. Every output is marked unvalidated with native encoding unresolved.

The supplied fixture is synthetic and contains no owner log data. Tests cover
clearing, source arbitration, independent freshness, delayed-event rejection,
input validation, HTML escaping and refusal to overwrite an existing preview.

### Native contract observation replay

`tools/navigation_contract_replay.py` adds a separate offline inspection stage
for native events that an analyst has normalized into `{at, signal, payload}`
records. It maps recognized numeric fields to the statically observed attribute
names, reports partial updates and observed value sets, and retains raw state
per signal. It does not convert those raw numbers into semantic turn names or
claim either screen shows them.

```powershell
python tools/navigation_contract_replay.py fixtures/navigation/native-contract-synthetic.jsonl
```

The fixture's numbers (including icons 91 and 92) are deliberately synthetic;
they are not discovered turn codes. Inputs accept signed 32-bit integers only,
reject booleans/floats, and require chronological timestamps. This analysis input
schema is stricter than a complete JSONCpp compatibility model. Unknown fields
are reported and left unencoded: in particular destination `distance` and
`second` are not silently fed into next-turn distance.

`--origin normalized_capture` labels analyst-normalized capture data; it does
not authenticate its provenance. Every result remains hardware-unvalidated with
display routing and enum meanings unresolved. This is not a raw analytics-log
decoder, a native message encoder or a vehicle output path. A future capture
adapter can use this schema once an observation route exists.

The suite now has 18 tests: nine semantic-policy tests, five contract-inspection
tests and four binary-backed dispatch tests. The last four require the ignored
local receiver and analysis dependencies; without them they are explicitly
skipped. With dependencies enabled, all 18 passed.

## Remaining completion gates

| Task | Delivered offline | Still required |
| --- | --- | --- |
| T02 | [Access/recovery worksheet](diagnostic-access-and-recovery.md), including absent-menu owner observation | Hardware identity, exposed observation route, authenticated access, measured layout, backup and bench restore; no spare available |
| T03 | Callback slots/copy/gate, reviewed setup caller and configured metadata, isolated dispatch probes | Full typed ABI/lifetimes/threading, other registration paths and runtime observation |
| T04 | Producer formats plus consumer integer mappings; per-screen capture plan | Captured messages, enum meanings, distance encoding, routing and timing for each screen |
| T05 | Tested semantic replay/preview plus native contract observation replay | Raw-capture adapter and semantic translation into the validated native model after T03/T04 |

No task in this table is being marked fully complete. There is no on-unit
installer, flash package or car-network output in this prototype.
