# Prioritized Subaru XV customization backlog

Agreed constraints: preserve the stock Android Auto integration, leave bootloader
and recovery components intact, and retain a demonstrated return to stock.
Applies to the supplied EU High `Rel_A2.24.41.20` image and the owner's 2017 XV.
The owner confirms stock TomTom turn instructions on both secondary displays.

## Governing requirement: reversible changes

Avoiding a bricked unit in the owner's car takes precedence over every feature.
Reversibility is a deployment requirement, not an assumption based on having a
stock update USB. No head-unit modification is currently cleared for deployment:
diagnostic execution access and independent recovery remain unproven.

- Continue extraction, static analysis, PC prototypes and replay tests offline.
  Stock log export is an observation step; it does not establish recovery.
- Test experimental execution and restore procedures on matching spare bench
  hardware first. The owner's installed unit is not the recovery test target.
- Before any proposed on-unit change, document exactly what it writes, its
  disable/removal procedure, and recovery if the HMI or normal startup fails.
  Verify backups include the affected files and any required unit-specific data.
- Prefer manually started, isolated additions with no automatic startup changes
  or stock-file replacement. A process running in RAM is not automatically safe:
  its storage writes and service/device interactions must also be understood.
- Keep bootloader, startup IFS, partition tables, RH850 and recovery/update
  components untouched. Do not flash experimental firmware onto the car's unit.
- Deployment requires a demonstrated return to stock on matching bench hardware,
  including a test with the extension failing or unavailable, followed by checks
  of stock Android Auto and essential head-unit functions. If recovery depends
  on the failed application still working, it is insufficient.

These conditions reduce risk; they do not establish a zero-risk guarantee. If a
feature cannot meet them, keep it as an offline prototype or external accessory.

This backlog separates achievable investigation/prototyping deliverables from
features whose installation is still conditional. Priority reflects useful
results and the recovery requirement, not just implementation difficulty.

Owner decision: wireless Android Auto will use an external adapter. T01 is
deferred and excluded from active development. Task IDs remain unchanged;
active priorities below have been renumbered.

## Completed foundation

- Inventoried and hashed the stock package.
- Verified its signature and payload metadata bindings under the bundled public key.
- Extracted the system, updater, navigation software and nested application images.
- Identified the stock navigation/display interfaces and Android Auto callback code.
- Verified that the supplied receiver's projection transport is USB-only.

## Execution order

| Priority / ID | Task | Concrete result | Conditions / feasibility |
| --- | --- | --- | --- |
| 1 — T02 | Establish diagnostic access and recovery | Exact unit/board identity, measured storage layout, verified backups and a demonstrated stock restore on matching bench hardware | Required before head-unit modifications. Access and recovery are not yet established. |
| 2 — T03 | Resolve Android Auto navigation callback registration | A documented callback ABI, endpoint settings and the exact point where turn/distance data becomes available or is omitted | Can continue offline now. Deliverable is a verified integration design, not an installed feature. |
| 3 — T04 | Validate both native display contracts | Captured stock navigation signals, turn-icon mappings, distance units/scaling and display-specific timing | Static analysis can continue now; validation needs read-only observation through T02 diagnostic access. |
| 4 — T05 | Build an offline navigation bridge prototype | Replayable captured/synthetic navigation events translated into the validated native data model, with cancellation, stale-data clearing and arbitration | Achievable on a development computer. Depends on T03/T04 contracts; initially has no car-network output. |
| 5 — T06 | Implement a removable native navigation bridge | Android Auto turn arrows and distance on both existing secondary displays while retaining stock projection | Main head-unit feature target. Conditional on T02–T05 and a reversible runtime execution mechanism. Additional callback integration may be needed if data is not exposed to another process. |
| 6 — T07 | Add richer navigation fields | Road names, ETA and lane information where both source and display support them | Follow T06; implement only fields actually available. Full-map video is not included. |
| 7 — T08 | Improve media metadata and diagnostics | Targeted track/artist display improvements or connection/error logging for an identified need | Existing service paths are promising. Inventory/replay tools can be built offline; head-unit deployment requires T02 and reversible access. |
| 8 — T09 | Customize selected native visual assets | A reviewed icon/background/theme prototype and a list of replaceable assets | Offline previews are achievable. Installation depends on asset loading and reversible access. Subaru HMI changes do not automatically change the phone-rendered Android Auto UI. |
| 9 — T10 | Add a small native information application | A custom page using data already exposed to the infotainment system | Lower priority. Requires a compatible QNX toolchain, rendering/audio/input integration as applicable, runtime access and resource testing. |

T01 is deferred; no custom wireless bridge development is planned. T03 and the static part of
T04 can proceed while hardware access/recovery are being established. T02 is a
deployment dependency; it need not block offline research or previews.

## Completion criteria for the first useful features

### T01: deferred; external adapter selected

The owner will use an external adapter for wireless Android Auto. No adapter
model or successful compatibility test has been recorded. Retest the eventual
navigation bridge with that adapter as well as the direct wired connection.

### T02: head-unit deployment prerequisite

Document the exact hardware and an authenticated diagnostic connection before
depending on root execution or service access. Backups must cover the relevant
storage/configuration and unit-specific data, not merely the stock USB package.
Demonstrate the restore path when the normal application is unavailable, and
verify Android Auto afterward. Existing dual boot copies and update scripts are
not sufficient evidence of independent recovery.

No task authorizes changing MLO, the startup IFS, RH850 firmware/bootloader,
partition tables or recovery/update components. If a proposed deployment requires
those writes or lacks a demonstrated restore path, it does not meet this backlog's
constraints and remains an offline prototype.

### T06: Android Auto instructions on both displays

Use the existing navigation display paths; do not assume both screens accept
identical fields or timing. Resolve conflicts with built-in TomTom navigation,
clear stale guidance on disconnect/cancellation, and make the extension easy to
disable. Confirm stock Android Auto audio, calls, controls and camera priority
with the extension enabled, disabled and stopped unexpectedly.

## Deferred research, not committed features

| Topic | Why deferred |
| --- | --- |
| T01: custom external wireless bridge | Owner selected an external adapter; custom bridge development is deferred. |
| Native wireless Android Auto inside the head unit | The shipped receiver has an explicit USB-only path. Requires new transport/bootstrap software or a different receiver, plus radio/driver validation and a recovery-compatible deployment. |
| Full receiver replacement using AASDK/OpenAuto | Possible research starting points, not compatible QNX replacements. Requires substantial platform and OEM integration work. |
| A newer commercial receiver SDK | No compatible newer binaries/source or integration agreement has been established for this unit. |
| Full Android Auto map/video on the secondary displays | No compatible graphics/video path has been established. Existing turn-instruction capability does not prove map rendering capability. |
| General home-screen/layout or behavior changes | The native HMI is compiled; exposed configuration limits and a concrete desired behavior must be established before estimating implementation. |

The map database and licensing remain outside the initial feature work. Keep the
complete stock package intact; navigation software stays in scope for its display
interfaces.

## Suggested next work

The next software task is **T03: trace navigation callback registration in the
Cinemo/Harman wrapper**. **T02: diagnostic access and recovery** is the highest
active priority and a prerequisite for head-unit feature deployment. Wireless
connectivity is left to the owner's external adapter.

Evidence: [initial assessment](firmware-assessment.md),
[offline extraction and interface analysis](offline-analysis-results.md),
[display-interface index](android-auto-display-interfaces.json), and
[wireless transport verification](wireless-android-auto-verification.md).
