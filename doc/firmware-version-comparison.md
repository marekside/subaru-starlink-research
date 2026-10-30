# Stock package comparison: A2.24.41.20 and A2.25.15.20

Compared offline on 2026-10-30. Both complete directory trees are now present:

- `usbUpdateStock_Rel_A2.24.41.20/KaliSWDL`
- `usbUpdateStock_Rel_A2.25.15.20/KaliSWDL`

The newer package's build log and extracted `sys1/etc/version.txt` both identify
`Rel_A2.25.15.20`, matching the owner's system-information photograph. Both are
EU High, platform label MY2017. The renamed older tree matches the previously
recorded hashes for all hashed files; map files were not in that baseline.

## Result relevant to our tasks

The key receiver, wrapper, display service, HMI and navigation application files
are byte-for-byte identical. The earlier callback and USB-only transport audits
were rerun successfully against the newly extracted matching-version files.
The static conclusions therefore apply to both packages, rather than relying
only on the older package's similarity or release name.

| Component in matching-version package | Comparison | Consequence |
| --- | --- | --- |
| `libNmeAndroidAuto.so` | Identical SHA-256: `32f5e8847c033a283bbfcc6b465d08b5ab6a4ee0a2d92b6cb51369346dae8a97` | Same USB-only projection transport and navigation callback dispatch |
| `libGALSVC.so` | Identical SHA-256: `49b8f393b866773520f22c0e64e98d5c8df4bfc6e291ee70cfa2c71872dc8dde` | Reviewed registration still leaves the three navigation-data callbacks null |
| `MFDService` | Identical SHA-256: `4fd028f843a8747be8c5f37c0d493ed0f80eb1c96eeac2b3d8f789c63a58fb04` | Same statically traced display handlers and integer-field parser |
| All 988 HMI regular files, including `Andromeda` | Identical content | Same embedded export callbacks/menu resources; does not prove menu exposure on the unit |
| All 1,277 extracted navigation regular files | Identical content | Same extracted navigation application/software; map database is a separate payload |

T02 remains open: neither the new package nor these comparisons establishes
authenticated access, a backup of unit-specific data or independent recovery.
T03 still needs the full ABI/other registration paths; T04 still needs captured
signals and per-screen validation. The T05 semantic prototype remains offline.

## Integrity and extraction

- Both inventories compute SHA-256 for all non-map files and confirm the supplied
  ISO MD5. Map subtree hashes were intentionally skipped; no map/licensing
  equivalence is claimed.
- The newer ISO's RSA-2048 PKCS#1 v1.5 SHA-256 signature and body hash pass under
  the bundled key. All five signed payload-metadata references pass as well.
  The extracted public-key file is identical between releases. This is verification
  relative to the bundled key, not independent OEM trust or an on-unit install test.
- All 665 clusters in `system.dat` (462), `swupdate.dat` (84) and `navsw.dat`
  (119) pass AES-GCM authentication and offline decompression. The new extracted
  decoder matches the existing hash-pinned decompression routine.
- Both QNX6 superblock checks and the nested IFS checksums pass. No stock input
  was repacked, patched or executed as a QNX process. Only the previously bounded
  pure decompression routine runs under Unicorn.

## What changed

| Extracted group | Old/new regular-file counts | Content changes |
| --- | --- | --- |
| Main startup IFS | 198 / 198 | `etc/system/config/fram.conf`: generator timestamp comment only |
| Updater mini IFS | 252 / 252 | None |
| Reverse-camera IFS | 63 / 63 | None |
| System filesystem | 1,213 / 1,213 | Five nested IFS container files |
| Updater filesystem | 59 / 59 | `minifs.ifs` and `rvcfs.ifs` containers |
| Navigation filesystem | 1 / 1 | `nav.ifs` container |
| Core application IFS | 47 / 47 | None |
| System application IFS | 603 / 603 | `sys1/etc/version.txt` and `sys1/etc/persistency_mgr/pmem_keyvalue.ini` |
| HMI IFS | 988 / 988 | None |
| Second application IFS | 151 / 151 | None |
| Third application IFS | 12 / 12 | None |
| Navigation IFS | 1,277 / 1,277 | None |

`version.txt` changes the version label and build date from 2024-10-12 to
2025-04-10; its package list is unchanged. The persistence configuration changes
only its generator timestamp comment. No paths were added or removed in these
manifest groups, and no type/mode/owner/symlink-target differences were found
apart from the listed file-content differences. Timestamps/inodes are compared
separately; the table does not count nested containers and their contents as
distinct functional updates.

Both ISOs have 83 regular files. Only the main startup IFS, map file log,
mini IFS and reverse-camera IFS differ by file hash. The extracted ISO's MLO,
RH850 payloads and remaining regular files are identical. This observation
does not authorize writing any boot/recovery components.

The outer encrypted `gracenote.dat` and `misc.dat` files also differ, but have
not been decrypted/compared in this pass. Their signed metadata was verified;
their complete ciphertext authentication and extracted-content equivalence
were not tested. `map/content/map.dat` changes size from 11,170,268,800 to
11,458,420,352 bytes; map/license content was not analyzed. Do not describe the
entire release as merely a version-label change.

## Reproduction and local records

New extractions and comparison records are under ignored
`analysis/rel-a2.25.15.20/`. Older extractions remain under `analysis/`.
Private firmware/key material stays outside source-controlled reports.

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'analysis/python-deps')
python tools/compare_firmware_manifests.py analysis analysis/rel-a2.25.15.20
python tools/audit_navigation_callbacks.py --analysis-root analysis/rel-a2.25.15.20
python tools/verify_android_auto_transport.py --receiver analysis/rel-a2.25.15.20/second1/files/second1/MediaOne/cinemo/libNmeAndroidAuto.so --wrapper analysis/rel-a2.25.15.20/second1/files/second1/lib/libGALSVC.so --output analysis/rel-a2.25.15.20/wireless-transport-repeat.json
```

The wireless verifier refuses existing output files; choose a new filename on
each run. Local records include `manifest-comparison.json`,
`iso-comparison.json`, `navigation-callback-audit.json` and
`wireless-transport-audit.json`, plus the three payload extraction reports.
The two inventories and newer authentication report are in `analysis/` with
`rel-a2.24.41.20-` / `rel-a2.25.15.20-` prefixes.
