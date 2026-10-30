# T02: diagnostic access and recovery worksheet

Status: offline preparation only. No authenticated connection, measured storage
layout, complete unit backup or demonstrated restore has been obtained. No
experimental deployment to the owner's installed unit is cleared.

Owner update, 2026-10-30: only the installed unit is available; no matching spare
is available for bench testing. The special menu has no **Download Analytics
Data** entry. Only the firmware version is known; the part number remains unknown.
The documented USB analytics procedure below therefore is not established on
this unit. Do not attempt to enable it by editing configuration or firmware.

Subsequent owner photos show **Factory Settings > Connection** and installed
software **`Rel_A2.25.15.20`**. The supplied package's `KaliSWDL.log` says
**`Rel_A2.24.41.20`**. This supersedes the earlier assumption that they match.
The photo shows a connection-status page, not a complete inventory of every
diagnostic menu, and not the Dealer Settings page described by the bulletin.
It does not establish that an export option is absent from all menus. No access
sequence for a different menu has been validated on this installed build.

Package follow-up: both stock releases are now present. The new
`usbUpdateStock_Rel_A2.25.15.20/KaliSWDL` identifies the matching version, passes
the offline authentication checks, and contains identical receiver/wrapper,
display-service and HMI files. See [comparison](firmware-version-comparison.md).
This closes the package-version gap, not the access/recovery gap.

## Identity and available access

| Item | Current evidence | Needed to close the gap |
| --- | --- | --- |
| Vehicle | Owner: 2017 Subaru XV | Record market and head-unit identity separately from vehicle year |
| Installed software | Owner photo and newly supplied package: `Rel_A2.25.15.20`; relevant files compared | Runtime validation remains required; no downgrade |
| Head-unit part number / board revision | Unknown | Identification label or existing service documentation; do not dismantle the installed unit for this worksheet |
| Matching spare | Owner has only the installed unit | Exact part number and compatible spare before bench testing |
| Stock USB analytics export | Owner reports no entry; photo shows Factory Settings connection page | Find an actually exposed stock observation route; no archive is available |
| Authenticated diagnostic execution | Not established | Confirmed supported access and credentials on matching bench hardware |
| Complete backup / independent restore | Not established | Measured layout, checked backups and a tested bench restore |

The shipped `startNetwork.sh` includes ASIX USB Ethernet setup and `inetd`;
`etc/inetd.conf` includes an SSH entry. This does not prove that networking runs
in the installed operating mode, that a particular adapter works, or that any
credentials are available. Do not run the script as an access experiment: it
starts/reconfigures USB and network services. Old passwordless-account methods
from the original research do not match the extracted account file.

### Starter configuration traced offline

`tools/inspect_diagnostic_startup.py` parses the matching package's
`core1/etc/subaru_starter.cfg` and resolves readiness dependencies by name:

| Configured process | Required interfaces/files |
| --- | --- |
| `io-pkt-v6-hc` | No nonempty required-interface entry in this process block |
| ASIX driver mount | `/dev/socket`, `/tmp/start_update` |
| `if_up -p en0` | `/dev/socket`, `/tmp/start_update` |
| `inetd` | `/dev/socket`, `/tmp/start_ti_ipc`, `/tmp/ifs_second1_ready`, `/tmp/start_non_critical` |

Thus network/SSH support is referenced by the regular starter configuration,
not only an isolated helper script. It is still not evidence that all gates are
satisfied in the owner's operating mode, that a working network address is
available, or that credentials exist. The marker name `start_update` does not
by itself establish the mode or code that produces it. No marker files should
be created to force these services; no such change or connection was attempted.

```powershell
python tools/inspect_diagnostic_startup.py
```

The output contains configuration evidence only. The local record is
`analysis/rel-a2.25.15.20/navigation-deep/diagnostic-startup.json`.

## Documented USB export: not exposed in the owner's menu

Use the Harman section on page 12 of
[Subaru bulletin 15-304-22](https://static.nhtsa.gov/odi/tsbs/2022/MC-10225755-0001.pdf#page=12).
With the vehicle parked, use an empty FAT32 USB drive, preferably at least 4 GB,
separate from firmware-update media. From Home, insert the drive and use the
HOME plus six TUNE/SCROLL presses sequence to open Dealer Settings. Select
**Download Analytics Data**, wait for completion, acknowledge OK and remove the
drive. Preserve the compressed export on the PC. This is reference information,
not a verified available procedure for the owner's unit; the owner reports the
entry is missing. Do not substitute update/reset commands.

The extracted HMI `Andromeda` has `copyAnalyticsDataToUSBCb`,
`cancelCopyAnalyticsDataToUSBCb` and `onAnalyticsDataCopyStatus` symbols. Its
separate **Core Dump Logs to USB** functionality must not be assumed to produce
the same archive. That label is also embedded in the compiled QML, but its menu
entry/access sequence has not been verified on the installed unit. Do not force
it by changing product settings. Neither export is a complete storage backup or
live bus trace. Static findings are under
`analysis/navigation-audit/diagnostic-menu-strings.json`.

If an exposed export route is established, make separate exports after native
TomTom and Android Auto guidance scenarios.
Keep a timestamped action record and observations for each display. First inspect
what was exported; only then decide whether a dedicated live trace is needed.
Do not assume the analytics format is plaintext or already supported by our tools.

## Recovery evidence required before modifications

1. Identify matching spare hardware and record the stock startup and Android Auto
   behavior. No recovery experiments on the owner's installed unit.
2. Establish an authenticated observation connection on the spare without changing
   boot/recovery components. Record how access is obtained and whether it remains
   usable if the HMI or proposed extension is unavailable.
3. Measure the storage layout read-only, including device sizes and relevant boot
   areas. Script paths below are hypotheses to compare against the measurements.
4. Identify all storage/configuration affected by the proposed extension and all
   unit-specific data needed for restoration. Preserve originals and hashes on
   separate storage; check read completeness and error handling. A backup from
   another unit is not automatically suitable.
5. Demonstrate extension removal and return to stock on the spare, including an
   extension failure/unavailable application. Do not intentionally corrupt boot
   components to test recovery. Record the independent recovery mechanism and
   verify it does not depend on the failed application.
6. Verify stock boot, Android Auto, audio/calls, controls and camera priority after
   restoration. Until this evidence exists, keep feature execution offline.

No destructive backup/restore commands are supplied: target devices, sizes and
the recovery mechanism have not been measured. A successful stock USB update
from a working HMI does not demonstrate recovery from a nonbooting unit.
Installing the supplied older package is not a recovery experiment or an
approved next step; downgrade acceptance and consequences are unverified.

## Storage hypotheses from stock scripts

| Purpose | Script device path |
| --- | --- |
| system | `/dev/emmc0t177` |
| writable data | `/dev/emmc0t177.1` |
| updater filesystem | `/dev/emmc0t177.2` |
| Gracenote | `/dev/emmc0t177.3` |
| apps | `/dev/emmc0t177.4` |
| misc | `/dev/emmc0t177.5` |
| navigation software | `/dev/emmc0t177.6` or `/dev/emmc1t177.1` |

The updater also contains boot-area writing and boot-configuration tools. Their
presence is not authorization to use them. MLO, startup IFS, RH850, partition
tables and recovery/update components remain outside permitted feature changes.

Stock artifacts remain under the two `usbUpdateStock_Rel_A2.*` folders; extracted/private observations
belong under ignored `analysis/`. Keep credentials and unit-specific backups out
of source-controlled reports. See [offline recovery findings](offline-analysis-results.md#recovery-findings-are-firmer-but-recovery-remains-unproven).
