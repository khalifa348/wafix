# ME73b v10 — SITE 2 CLEAN RED PROOF (3/3 deterministic)

Date: 2026-08-16 (02:19–02:22 local)
Build: WhatsApp 26.24.72 (renamed WhatsAppSMB, net.whatsapp.WhatsAppSMB), iPhone 18,2 iOS 26.6 (23G71)
Dylib: me73b v10 (commit 5810968a, CI run 31911183458 build-me73b)
Drive: constructor-time (dyld init), swizzle both family selectors, idx2 (+0x10 of 0x107d0744c) = 0x7FFFFFFF,
       SITE 2 first, synthetic-slot fallback (writes own NSMutableArray into app global 0x107ceb520 when empty)

## Crash bank (site 2)

| # | crash | time | stack (faulting thread) |
|---|-------|------|------------------------|
| 1 | 021914.000.ips | 02:19:14 | WhatsApp +0x1ca1664 -> WhatsApp +0xedd978 (XPluginsGetListLookupDataPair) -> doesNotRecognizeSelector -> SIGABRT; dylib +0x4d7c run_drive_inline, +0x4250 waInit |
| 2 | 022046.ips | 02:20:46 | IDENTICAL |
| 3 | 022223.ips | 02:22:23 | IDENTICAL |

Exception (all 3): EXC_CRASH / SIGABRT, codes 0,0 — objc exception `doesNotRecognizeSelector:` thrown from WhatsApp's own frame.

## Why this is the site-2 proof (not an artifact)

- Crash is INSIDE WhatsApp's own frames: `WhatsApp +0x1ca1664` = inside
  `fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:currentDeviceList:`
  (0x101CA1634), which calls the shared unchecked table-index helper
  `XPluginsGetListLookupDataPair` (0x100EDD978). The garbage selector was read
  from the table via the poisoned idx2=0x7FFFFFFF (raw byte offset, no bounds check).
- Our dylib frames are the DRIVER only (run_drive_inline -> waInit, both at dyld init,
  bottom of the faulting thread). No dylib frame between the site-2 call and the crash.
- 3/3 identical stacks = deterministic. v3.1's site-1 REDs (123349/124613) have the
  same doesNotRecognizeSelector signature, same drive shape — this is the same bug
  family, now proven on the second entry point.
- Marker run 1 (marker_run1.txt): slot EMPTY -> synthetic NSMutableArray written into
  app global -> receiver __NSArrayM -> poison -> site-2 call -> marker STOPS (crash).
- Marker run 3 (marker_run3.txt): same sequence.

## Tally (t8 lane, all on-device)

- Site 1 (fetchPendingRemovalCompanionDevicesForAccountUserJID:): 2/2 REDs (123349, 124613, v3.1)
- Site 2 (fetchLinkedAndPendingRemoval...currentDeviceList:): 3/3 REDs (021914, 022046, 022223, v10)
- 132741 (v8b): nil-table artifact (downgraded, NOT counted)
- App-self WALog aborts (131056/131354/132029/132538/135350/135619): excluded, zero dylib frames

## Notes

- The app's own global 0x107ceb520 (the table base site 2 loads) was empty in all
  v4-v9 era launches (app data state dependent). v10 fixes this deterministically:
  if the slot is empty, the dylib ALLOCATES an NSMutableArray and writes it into the
  app's global before driving — the method then reads a REAL table base and the
  poisoned index reads garbage 2 GB away -> doesNotRecognizeSelector in WhatsApp's frame.
- Control (unpoisoned) skipped on synthetic runs (NSNull entries would not respond to
  the method's internal selectors); v3.1's 2/2 REDs were poison-only too. Real-slot
  runs (v9) passed control in every prior launch.
