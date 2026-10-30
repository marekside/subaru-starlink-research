# Wireless Android Auto verification

Verified on 2026-10-30 against the supplied EU High `Rel_A2.24.41.20` firmware.

## Answer

**The Android Auto receiver shipped in this image uses USB-only projection
transport. Native Wireless Android Auto is not implemented by this stock path.**
This is a finding about the actual bundled binaries, not a claim about all
Cinemo releases. It supersedes the earlier statement that wireless support was
merely unverified. It is based on an explicit protocol check and transport
construction, not the absence of Wi-Fi-related strings.

## Evidence

The code addresses below are ELF virtual addresses relative to the shared
library's load base, not file offsets. The receiver mixes ARM and Thumb code;
the protocol and transport functions below use ARM instructions.

### 1. The receiver explicitly accepts USB and rejects other transports

In `libNmeAndroidAuto.so`, the worker routine starting at `0x2e414`:

1. Copies the configured URL and extracts its protocol using
   `NmeString::url_protocol`.
2. Removes an optional outer `aoap` prefix.
3. Extracts the next protocol and compares it case-insensitively with **`usb`**.
4. Goes to session startup only when that comparison matches. Otherwise it
   follows an error path, optionally logs `Protocol "%s://" is not supported!`,
   and returns error value `0x0b`.

The comparison call is at `0x2e4b4`; `0x2e4c4` tests its saved result and
`0x2e4c8` branches to the USB success block at `0x2e570`. That block strips the
protocol and calls the session-start routine at `0x2d590` via `0x2e580`.

Equivalent pseudocode for this decision:

```text
url = configured_url
if protocol(url) equals "aoap":
    remove_protocol(url)
if protocol(url) does not equal "usb":
    report_unsupported_protocol()
    return 0x0b
remove_protocol(url)
begin_session(url)
```

The resolved protocol string addresses are `0x14ef28` (`aoap`) and `0x14ef30`
(`usb`). There is no alternate TCP/Wi-Fi branch in this dispatch decision.

### 2. Session startup constructs the USB transport directly

The session-start routine calls `ThreadSetupTransport` at `0x2b12c` through
the instruction at `0x2e160`. That setup routine directly allocates and constructs
its transport via a call at `0x2b224` to constructor `0x509ac`.

The constructor stores the derived vtable `0x180d18` at `0x50db0`. Its RTTI
at `0x180d2c` resolves to `26NmeAndroidAutoUSBTransport`, independently identifying
the constructed class. The setup routine calls its initialization function at
`0x4ea48` through `0x2b290`. Initialization calls
`NmeClassFactory::CreateUSBLib` at `0x4eab4`, followed by USB interface operations.

These are concrete USB operations, not a generic network transport with an
unobserved wireless setting. The receiver's imports also lack the surveyed
socket-connection and dynamic-plugin-loader entry points; this is corroboration,
not the basis of the conclusion.

### 3. Harman's wrapper supplies a USB session URL

`libGALSVC.so` exports `GALSvcCinemoIntSetURLPath` at Thumb address `0x19fdd`
(instruction address `0x19fdc`). It constructs a URL using the literal `usb:///`
at `0x29ec8`, appends the selected device path, and passes the result through the
Cinemo application's virtual interface at `0x1a108`.

Wi-Fi services elsewhere in the image do not change this URL gate or the
receiver's constructed transport. Bluetooth pairing support inside the receiver
also does not imply wireless projection support.

## Scope and practical consequence

The definitive answer for this supplied stock image is **no native Wireless
Android Auto through its existing Cinemo/Harman projection implementation**.
Changing a Wi-Fi setting or enabling an existing configuration flag cannot add
the missing network projection transport.

Native wireless operation would require additional or replacement software,
including transport/bootstrap integration, and validation of the radio/driver
capabilities. This audit does not establish whether the physical hardware could
support such a future implementation. A wireless-to-USB adapter is a separate
approach that continues to use the existing USB receiver.

No numeric Cinemo SDK release was established, so the finding should not be
generalized as "Cinemo version X never supports wireless." No on-unit wireless
connection test was performed, and no firmware was modified or installed.

## Reproducibility

The inspected libraries match the SHA-256 values in their original extraction
manifest:

```text
libNmeAndroidAuto.so
32f5e8847c033a283bbfcc6b465d08b5ab6a4ee0a2d92b6cb51369346dae8a97

libGALSVC.so
49b8f393b866773520f22c0e64e98d5c8df4bfc6e291ee70cfa2c71872dc8dde
```

[verify_android_auto_transport.py](../tools/verify_android_auto_transport.py)
reproduces the protocol constants, branch instructions, call targets, import
resolution, constructor RTTI and wrapper URL prefix for these exact binaries.
It rejects different binaries instead of applying the conclusion to them.

With the previously installed analysis dependencies:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'analysis/python-deps')
python tools/verify_android_auto_transport.py
```

The output is `analysis/wireless-audit/verification.json`. Use a new `--output`
path for a repeat run. Supporting disassemblies and candidate-reference searches
are in the same ignored directory. The reference finder is a search aid; the
transport conclusion rests on the manually reviewed instructions above.
