# ME73 — t7 RETRACTED (superseded by FINAL_REPORT.md rev. 3)

> **⚠️ RETRACTED 2026-08-16.** This file was written before the control tests. The crashes
> below are **harness artifacts**, not a server-stanza-driven bug: ME73c proved the crash is
> count-INDEPENDENT (count=100 faults byte-identically to 0x7FFFFFFF — faults within 0x50 vs
> the 4 GB apart a count-driven index would produce), and the "control" never ran. See
> `FINAL_REPORT.md` (Correction 1) for the full falsification. Kept for the record.

**Date:** 2026-08-15 07:50 (device reconnected, ME73_inj_signed.ipa installed 07:49:54)
**Device:** iPhone 18,2 (T8150), iOS 26.6 (23G71), jailed
**Build:** net.whatsapp.WhatsAppSMB 26.24.72 (test copy of pristine App Store build) + libwaContainerFix.dylib (105,360 B signed)
**Lead:** t7 — `didOfflineResumeStartWithType:totalStanzasCount:` (category WAIncomingMessageHandlingMain / WAMessageBatchingConfigurator) — server-supplied count drives unchecked table index in Swift helper @0x100337b88 / thunk region 0x1003379e0.

## Original claim (RETRACTED): "DETERMINISTIC CRASH 2/2 — first server-stanza-driven fault"

| Crash | Time | Fault | WhatsApp frame | Drive orig (x8) |
|---|---|---|---|---|
| WhatsApp-2026-08-15-075024.ips | 07:50:23.8 | SIGSEGV KERN_INVALID_ADDRESS @0x18f0 | **0x3379ec** (XPluginsGetListLookupDataPair) | 0x10291f9e0 |
| WhatsApp-2026-08-15-075030.ips | 07:50:30 | SIGSEGV KERN_INVALID_ADDRESS @0x1a48 | **0x3379ec** (XPluginsGetListLookupDataPair) | 0x1051339e0 |

Stack (both identical):
```
[libobjc.A.dylib] objc_retain +16                      ← faulting
[WhatsApp]        0x3379ec                             ← t7 site (bl 0x10001a298 at thunk 0x1003379e0)
[libwaContainerFix] run_drive_inline +284              ← ME73 drive (count=0x7FFFFFFF)
[libwaContainerFix] waInit +372                        ← dylib constructor
[dyld] findAndRunAllInitializers
```

Registers (075024 / 075030):
- x8  = 0x10291f9e0 / 0x1051339e0 → the swizzled orig selector addresses (both ASLR slides)
- x20 = 0x1, x24 = 0x6, x25 = 0xf0 → x25 = garbage table entry (expected valid pointer)
- x12 = 0x74 / 0x4112021fef0986e6 (garbage), x13 = 0x6f/0x6f, x16 = 0x18d0/0x1a2d

Marker diary (Documents/wafix_marker.txt, tail — persists across reinstalls):
```
[ME73] constructor complete; drive starting (2 blocks, 2 orig slides)
[drive] calling orig with type=1 count=0x7FFFFFFF...      ← DEAD HERE, no RETURNED
```
Marker dies exactly at the crafted-count call → crash INSIDE orig execution, before return.

## Timeline
- 07:48:56 WhatsApp-074856.ips = OLD ME72n build lead1 (0x389b80, x16=0x64, fault @0x80) — the pre-existing crash user observed
- 07:49:54 ME73_inj_signed.ipa installed (pymobiledevice3 apps install)
- 07:50:24 + 07:50:30 TWO IDENTICAL ME73 crashes (launch + auto-relaunch) at t7 site
- 07:51-52 crashes pulled + analyzed; evidence copied to teams/whatsapp/crash-logs/

## Interpretation
`totalStanzasCount` (server-supplied XMPP offline-resume field) → passed through swizzled orig → Swift code at 0x3379ec/0x337b88 does `ldrsw x8,[x8,#0x10]` → `ldr x25,[x21,x8]` unchecked → x25=garbage → `objc_retain` SIGSEGV. **Remote stanza data DIRECTLY drives the fault.** Reach: server-controlled count → crash. (Drive used 0x7FFFFFFF; a realistic server value that overflows the table needs on-wire validation — but the unchecked index is now proven in WhatsApp's own code, 2/2 deterministic.)

## Evidence files
- me73_crashes/WhatsApp-2026-08-15-075024.ips, -075030.ips (originals, zdl_stage)
- teams/whatsapp/crash-logs/ copies
- marker: zdl_stage/wafix_marker_me73b.txt
- parse_me73_ips.py (parser), inject_me73.py + me73.m (build), t7_scan_newest.py + find_bl2.py (static)
