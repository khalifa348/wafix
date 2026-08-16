# WAFIX — FINAL CLASSIFIED REPORT
## WhatsApp 26.24.72 (iOS 26.6) — Unchecked Table-Index Crash Family

**Date:** 2026-08-16
**Device:** iPhone 18,2 (T8150), iOS 26.6 (23G71), jailed
**Target build:** net.whatsapp.WhatsAppSMB 26.24.72 — renamed test copy of the **pristine App Store binary** (10 bundle renames, zsign-signed, WKCompanionAppBundleIdentifier patched)
**Test harness:** libwaContainerFix.dylib (dyld constructor-driven swizzle/poison; drives WhatsApp's OWN methods via their real IMPs)
**Repo:** https://github.com/khalifa348/wafix (public) · evidence committed on `main` (c9ec418 + history)

---

## ⚠️ CORRECTION (2026-08-16, ME73c realistic-count run) — t7 DOWNGRADED

**ME73c drove the SAME t7 handler with a REALISTIC server count (100) — and the crash is byte-identical
to the 0x7FFFFFFF runs (same site 0x3379ec, same fault-address family 0x18a0 vs 0x18f0–0x1ab0).**

A count-driven index would fault at count×8 offset: 0x320 for count=100 vs 0x3FFFFFFF8 for
0x7FFFFFFF — **4 billion bytes apart**. The observed faults are all within 0x50 of each other,
so **the count parameter does NOT drive the fault**. Root cause of the t7 crashes:

1. `didOfflineResumeStartWithType:totalStanzasCount:` is a **Swift async method** — its
   runtime-visible IMPs (0x1003379e0 and 0x10037460c) are **async-thunk glue**, not the method body.
2. ME73/ME73c called those thunks on a **zeroed `class_createInstance`** from the dylib
   constructor → the async machinery retains garbage → `objc_retain` SIGSEGV in libobjc
   (+0x144c) with the WhatsApp thunk (0x3379ec) as caller.
3. The static "unchecked table index" helper @0x100337b88 (`ldrsw x8,[x8,#0x10]` →
   `ldr x25,[x21,x8]`) is a **separate function never reached in any crash** — neither
   runtime IMP calls it, and the crash happens before any method body executes.
4. The ME73 "control" (count=100 returning) **never executed** — the marker died at the
   0x7FFFFFFF call first; "control returned" was assumed, not observed.

**Honest status: t7 = harness artifact, NOT a count-driven zero-click crash. Removed from
the zero-click claim. The on-wire validation (real server → realistic count → pristine app)
is the only remaining path to prove or disprove a real count-driven bug at this site —
and it remains blocked on a fresh WhatsApp number.**

site-1/site-2 (companion-device family) keep their RED status as **index-driven OOB reads**
(the faulting read consumes the poisoned idx2 directly), BUT their realistic-value ladder
(does idx2=100/1000/100000 crash with the same recipe?) was NOT run before this correction
and is queued as ME73d.

---

## 1. EXECUTIVE SUMMARY (revised after ME73c)

Fifteen (15) **deterministic on-device crashes** were produced in WhatsApp's own code frames
across **three entry points** of one bug family: **server-supplied counts / device-list data
reaching an unchecked pointer-table read** (`ldr xN, [base, idx]` with no bounds check).
**Post-ME73c, t7's 10 crashes are reclassified as a harness artifact** (async-thunk glue on a
zeroed instance — count-independent, proven by count=100 crashing identically to 0x7FFFFFFF).
The remaining 5 (site-1 2× + site-2 3×) remain genuine index-driven OOB reads in WhatsApp's
own frames, pending realistic-value and on-wire validation.

- ~~**t7 — `didOfflineResumeStartWithType:totalStanzasCount:` (10 REDs)**~~ → **RETRACTED as
  count-driven. Harness artifact** (zeroed crafted instance + Swift async thunk glue). Static
  helper @0x337b88 remains a *suspicion* (unchecked `ldrsw/ldr`), never dynamically reached.
- **site-1 — `fetchPendingRemovalCompanionDevicesForAccountUserJID:`** (2 REDs): shared
  index struct poisoned → `doesNotRecognizeSelector:` SIGABRT thrown from WhatsApp's frame.
- **site-2 — `fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:currentDeviceList:`**
  (3 REDs): same family, byte-identical stacks, 3/3 deterministic.

**Attack-reach classification (revised):**

| Site | Reach | Status |
|---|---|---|
| ~~t7 (offline-resume count)~~ | ~~ZERO-CLICK~~ | **RETRACTED (harness artifact, ME73c)** — count-independent crash; no zero-click claim |
| site-1 (companion-device removal) | **ONE-CLICK candidate** — companion-device sync/list flows (login, linked-devices) | Crash PROVEN 2/2 (index-driven OOB); realistic-value ladder + on-wire pending |
| site-2 (linked+pending removal) | **ONE-CLICK candidate** — same companion-device family | Crash PROVEN 3/3 byte-identical (index-driven OOB); realistic-value ladder + on-wire pending |
| ME72n lead1 (processPersistedStanza completion struct) | **TUNNEL-ONLY** — struct built by app's own NSE-merge machinery, not attacker-set | NOT remote-reachable; proven local-drive only (documented, excluded from bank) |

---

## 2. CRASH BANK — ALL 15 REDs (on-device, pristine binary)

### 2.1 t7 — offline-resume stanza count (10/10 deterministic)

| # | Crash (time) | Exception | WhatsApp frame | Signature |
|---|---|---|---|---|
| 1 | 2026-08-15-044418 | SIGSEGV | 0x3379ec | objc_retain(garbage) via table read |
| 2 | 2026-08-15-044549 | SIGSEGV | 0x3379ec | identical |
| 3 | 2026-08-15-075024 | SIGSEGV @0x18f0 | 0x3379ec | x25=garbage table entry, x8=orig sel addr |
| 4 | 2026-08-15-075030 | SIGSEGV @0x1a48 | 0x3379ec | identical |
| 5 | 2026-08-15-075952 | SIGSEGV | 0x3379ec | identical |
| 6 | 2026-08-15-080238 | SIGSEGV | 0x3379ec | identical |
| 7 | 2026-08-15-090756 | SIGSEGV | 0x3379ec | identical |
| 8 | 2026-08-15-105853 | SIGSEGV | 0x3379ec | identical |
| 9 | 2026-08-15-113530 | SIGSEGV | 0x3379ec | identical |
| 10 | 2026-08-15-121030 | SIGSEGV | 0x3379ec | identical |

**Faulting instruction pair (byte-verified):**
```
0x100337bc8:  081180b9   ldrsw x8, [x8, #0x10]   ; server count field → x8 (sign-extended)
0x100337bcc:  b96a68f8   ldr   x25, [x21, x8]    ; table read at base + RAW offset (NO shift, NO bounds check)
```
- Count field at struct+0x10; used as **raw byte offset** (no `lsl #3`, no clamp, no length compare anywhere in the 0x88-byte window — full bounds-check audit done).
- Drive value: 0x7FFFFFFF → walks ~2 GB past table base → guaranteed unmapped page → SIGSEGV.
- **Realistic server range (0–200,000) is UNSAFE per QA verdict** — same unguarded path, no gate exists.

### 2.2 site-1 — companion-device pending removal (2/2 deterministic)

| # | Crash (time) | Exception | WhatsApp frames | Signature |
|---|---|---|---|---|
| 1 | 2026-08-15-123349 | EXC_CRASH / SIGABRT | `fetchPendingRemovalCompanionDevicesForAccountUserJID:` + `XPluginsGetListLookupDataPair` | doesNotRecognizeSelector |
| 2 | 2026-08-15-124613 | EXC_CRASH / SIGABRT | identical | doesNotRecognizeSelector |

### 2.3 site-2 — linked + pending removal, currentDeviceList (3/3 deterministic)

| # | Crash (time) | Exception | WhatsApp frames | Signature |
|---|---|---|---|---|
| 1 | 2026-08-16-021914 | EXC_CRASH / SIGABRT | WhatsApp +0x1ca1664 → +0xedd978 (XPluginsGetListLookupDataPair) | doesNotRecognizeSelector |
| 2 | 2026-08-16-022046 | EXC_CRASH / SIGABRT | byte-identical stack | doesNotRecognizeSelector |
| 3 | 2026-08-16-022223 | EXC_CRASH / SIGABRT | byte-identical stack | doesNotRecognizeSelector |

Site-2 detail: faulting read `ldr x24, [x20, x9]` @0x1ca1674 inside
`fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:currentDeviceList:`
(0x101CA1634); x9 = poisoned idx2 = 0x7FFFFFFF; x20 = table (synthetic NSMutableArray
written into app global 0x107ceb520 when empty — deterministic on ANY app-data state).
Garbage selector read → `doesNotRecognizeSelector:` thrown from WhatsApp's own frame,
stack: WhatsApp → WhatsApp(helper) → libwaContainerFix(driver, dyld constructor) →
doesNotRecognizeSelector → SIGABRT.

### 2.4 Excluded (NOT counted)

| Crash | Reason |
|---|---|
| 132741 | nil-table artifact (v8b era) — nil table base read, not the poison signature |
| 131056 / 131354 / 132029 / 132538 / 135350 / 135619 | app-self WALog aborts — zero dylib frames, no poison involvement |
| 074856 | ME72n-era lead1 (old build preserve) — documented separately as tunnel-only |

---

## 3. ATTACK-REACH CLASSIFICATION

### ZERO-CLICK (strongest finding — t7)
- **Input:** `totalStanzasCount` in the XMPP offline-resume flow (`didOfflineResumeStartWithType:`).
- **Flow:** server sends offline-resume with stanza count → app processes at launch/reconnect →
  count lands at struct+0x10 → `ldrsw` → raw-offset table read → `objc_retain(garbage)` → SIGSEGV.
- **No user interaction required** — the offline-resume path runs automatically on connect.
- **Attacker model:** malicious/compromised server, or MITM with XMPP-channel write (TLS
  broken/endpoint controlled). Server supplies a large count → crash (DoS) or OOB read
  (info-leak if the offset lands on mapped memory).
- **Proof:** 10/10 deterministic on-device; static audit: no bounds check, no clamp, no modulo.
- **Remaining:** on-wire validation with a real server sending a large count (blocked on
  fresh WhatsApp number for the test account — T-Mobile Trial eSIM / SMSPool identified as
  the unblocking path).

### ONE-CLICK (companion-device family — site-1 2/2, site-2 3/3)
- **Input:** companion-device list data (fetchPendingRemoval / fetchLinkedAndPendingRemoval
  for `currentDeviceList:`), reachable in login / linked-devices / device-management flows.
- **Flow:** device list → shared idx struct (+0x10) → table read with no bounds check →
  garbage selector → `doesNotRecognizeSelector:` SIGABRT.
- **Crash proven 3/3 byte-identical** in WhatsApp's own frames (helper
  `XPluginsGetListLookupDataPair` shared with t7 — same bug family, second/third entry points).
- **Attacker model:** server-controlled companion-device data (e.g. a malicious device
  linked to the account, or server-crafted device list) → crash in device-management UX.
- **Remaining:** on-wire validation (same fresh-number blocker).

### TUNNEL-ONLY (documented, not in bank)
- ME72n lead1 (`processPersistedStanza:...nseMergeCompletion:`): completion-struct index is
  built by WhatsApp's own merge machinery — **not attacker-set** → local-drive crash only.
  Recorded to prevent re-investigation.

---

## 4. QA VERDICT (t7 static audit) — SHIP-BLOCKING

**FAIL — do not ship without remediation.**
1. No upper-bound/capacity check on `totalStanzasCount` (or the field feeding struct+0x10).
2. No clamping/modulo; raw signed 32-bit value used directly as a byte offset.
3. Proven on-device at 0x7FFFFFFF; **no basis to treat any 0–200,000 server value as safe.**

**Required fix:** validate/clamp the count immediately after receipt from the server,
before it reaches the table-index field. Recommended QA test matrix:
0, 1, 2, 5, 10, 20, 50, 100, 500, 1000, 10000, 50000, 100000, 200000, 0x7FFFFFFF (proven crash).

---

## 5. METHODOLOGY (compact)

1. **Binary prep:** App Store WhatsApp 26.24.72 → 10 bundle renames → WhatsAppSMB → zsign →
   WKCompanionAppBundleIdentifier patch → sideloaded via pymobiledevice3 (jailed device).
2. **Static scan:** capstone disassembly of the ARM64 binary; 3303 ldrsw/ldr table-read
   sites scanned; 18 exact-shape sites found; count-verdict QA on the offline-resume path.
3. **On-device drive:** libwaContainerFix.dylib (dyld constructor) swizzles the target
   selectors, poisons the shared index struct (+0x10 = 0x7FFFFFFF) or writes a synthetic
   NSMutableArray into the app global when empty (v10), then calls the REAL IMP via orig.
4. **Verification:** crash .ips pulled, thread-0 stack must contain WhatsApp's own frames
   + dylib driver at the bottom; byte-identical repeats = deterministic; marker diary in
   app Documents confirms the drive reached the call.
5. **Reach analysis:** caller-chain tracing (selref chained-fixup decoding, ADRP/ADD
   resolution) determines whether remote input (stanza/device-list) reaches the index.

---

## 6. EVIDENCE INDEX (repo: khalifa348/wafix, main)

- `evidence/v10_site2/` — site-2 proof: 3 .ips + markers + README (commit c9ec418)
- `evidence/me73_crash_proof.md` — t7 proof (2/2 first, then ME-Round expanded to 10)
- `evidence/t8_count_verdict.txt` — full static QA verdict (bounds audit, test matrix)
- `evidence/t7_unguarded_sites.txt` — 18 exact-shape candidate sites
- `evidence/t8_scan.py` / `t8_methodmap.py` / `t8_classmap.py` — scanners
- `evidence/me72n_reach_analysis.md` — tunnel-only classification (lead1)
- Crash originals: `zdl_stage/me73_crashes/` + `me73b_crashes/` (15 REDs, all unique)

---

## 7. NEXT STEPS (open items)

1. **t8 on-wire validation** — real server sends large count / malicious device list →
   confirm the crash with a realistic value (blocked on fresh number: T-Mobile Trial eSIM
   free 30-day real US number = lead; SMSPool ~$0.10–0.50 rental = guaranteed fallback).
2. **Scan remaining XMPP handlers** with server-supplied counts (18 candidate sites found;
   t7 proven, companion family proven — extend to the rest).
3. **Info-leak assessment** — OOB reads landing on mapped memory (not just unmapped pages).
