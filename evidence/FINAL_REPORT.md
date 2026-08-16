# WAFIX — FINAL CLASSIFIED REPORT
## WhatsApp 26.24.72 (iOS 26.6) — Unchecked Table-Index Crash Family

**Date:** 2026-08-16 (rev. 3 — ME73d/ME73e control-ladder falsification)
**Device:** iPhone 18,2 (T8150), iOS 26.6 (23G71), jailed
**Target build:** net.whatsapp.WhatsAppSMB 26.24.72 — renamed test copy of the **pristine App Store binary** (10 bundle renames, zsign-signed, WKCompanionAppBundleIdentifier patched)
**Test harness:** libwaContainerFix.dylib (dyld constructor-driven swizzle/poison; drives WhatsApp's OWN methods via their real IMPs)
**Repo:** https://github.com/khalifa348/wafix (public) · evidence committed on `main`

---

## ⚠️ CORRECTION 1 (2026-08-16, ME73c) — t7 RETRACTED

**ME73c drove the SAME t7 handler with a REALISTIC server count (100) — and the crash is byte-identical
to the 0x7FFFFFFF runs (same site 0x3379ec, same fault-address family 0x18a0 vs 0x18f0–0x1ab0).**

A count-driven index would fault at count×8 offset: 0x320 for count=100 vs 0x3FFFFFFF8 for
0x7FFFFFFF — **4 billion bytes apart**. The observed faults are all within 0x50 of each other,
so **the count parameter does NOT drive the fault**. Root cause of the t7 crashes:

1. `didOfflineResumeStartWithType:totalStanzasCount:` is a **Swift async method** — its
   runtime-visible IMPs (0x1003379e0 and 0x10037460c) are **async-thunk glue**, not the method body.
2. ME73/ME73c called those thunks on a **zeroed `class_createInstance`** from the dylib
   constructor → the async machinery retains garbage → `objc_retain` SIGSEGV in libobjc
   with the WhatsApp thunk (0x3379ec) as caller.
3. The static "unchecked table index" helper @0x100337b88 (`ldrsw x8,[x8,#0x10]` →
   `ldr x25,[x21,x8]`) is a **separate function never reached in any crash** — neither
   runtime IMP calls it.
4. The ME73 "control" (count=100 returning) **never executed** — the marker died at the
   0x7FFFFFFF call first; "control returned" was assumed, not observed.

**Status: t7 = harness artifact, NOT a count-driven crash. Retracted.**

---

## ⚠️ CORRECTION 2 (2026-08-16, ME73d + ME73e) — site-1 AND site-2 RETRACTED

The companion-device family was re-tested with a **proper control ladder** (ME73d = site-2,
ME73e = site-1): idx2 ∈ {0, 5, 100, 1000, 100000, 200000, 0x7FFFFFFF}, every step logged.

**Result: the CONTROL (idx2 = 0 — a valid, in-bounds index) crashed the app on BOTH sites,
byte-identical to the 0x7FFFFFFF "poison" runs:**

| Test | idx2 (index) | Result | Crash file |
|---|---|---|---|
| ME73d STEP 1 (site-2) | **0 (CONTROL)** | **CRASH** — doesNotRecognizeSelector SIGABRT, XPluginsGetListLookupDataPair | WhatsApp-2026-08-16-072737.ips |
| ME73d STEP 1 (site-2, relaunch) | **0 (CONTROL)** | **CRASH** — identical | WhatsApp-2026-08-16-072951.ips |
| ME73e STEP 1 (site-1) | **0 (CONTROL)** | **CRASH** — doesNotRecognizeSelector SIGABRT, same helper family | WhatsApp-2026-08-16-073720.ips |
| v10 poison runs (site-2, 3×) | 0x7FFFFFFF | CRASH — identical signature | 021914 / 022046 / 022223 |
| v3.1 poison runs (site-1, 2×) | 0x7FFFFFFF | CRASH — identical signature | 123349 / 124613 |

An index-driven OOB crash cannot fire at idx2=0 (in-bounds, array[0] = a real NSNull element).
**The crash is index-INDEPENDENT.** Root cause of the entire site-1/site-2 family:

1. The v10 harness wrote a **synthetic NSMutableArray of 256 NSNull entries** into the app
   global (0x107ceb520) when the real table was empty — and then called the WhatsApp method
   **with that synthetic array as the receiver (`[drive] receiver: __NSArrayM (SYNTHETIC)`)**.
2. The method (a `WAOwnDeviceStorageManagerMain` method) then messages elements/selectors of
   its receiver. NSNull does not respond to the method's internal selectors →
   `doesNotRecognizeSelector:` SIGABRT — thrown from WhatsApp's frame only because the method
   body IS WhatsApp's code.
3. The v10 marker literally recorded the flaw: **`[ctrl] SKIPPED — synthetic slot`** — the
   control was skipped because "NSNull entries would not respond to the method's internal
   selectors and crash the control" (v10 README). That is an admission that the crash was
   expected at ANY index. The control ladder now proves it: idx2=0 crashes identically.
4. The v3.1 site-1 runs (123349/124613) were **poison-only with no control at all**
   (v10 README: "v3.1's 2/2 REDs were poison-only too") — same unproven shape.

**Status: site-1 (2 REDs) and site-2 (3 REDs) = harness artifacts (synthetic NSNull receiver
artifact), NOT index-driven OOB crashes. Retracted. Crash bank total: 0 standing REDs.**

The **static** observation remains true and is worth a defensive fix: the companion-device
helper (`XPluginsGetListLookupDataPair`) and the t7 helper (@0x100337b88) do apply
**unchecked `ldr xN,[base,idx]` reads** (no bounds check, no clamp, raw signed 32-bit offset).
That is a code-quality/defense-in-depth finding — but **no dynamic proof of a count/index-driven
crash exists anymore**, and none can be produced with the synthetic harness. Only an on-wire
test (real server → realistic count/device-list → pristine app with a REAL initialized
storage-manager instance and REAL device list) can prove or disprove it — blocked on a fresh
WhatsApp number.

---

## 1. EXECUTIVE SUMMARY (rev. 3)

**All 15 on-device "REDs" have been retracted as harness artifacts after control-ladder testing.
Zero (0) crash findings currently stand as proven remote-reachable vulnerabilities.**

| Site | Method | REDs | Verdict | Evidence |
|---|---|---|---|---|
| t7 | `didOfflineResumeStartWithType:totalStanzasCount:` | 10 | **RETRACTED** — count-independent crash; zeroed-instance + Swift async-thunk artifact | ME73c: count=100 crashes identically to 0x7FFFFFFF (faults within 0x50) |
| site-1 | `fetchPendingRemovalCompanionDevicesForAccountUserJID:` | 2 | **RETRACTED** — control (idx2=0) crashes identically; NSNull synthetic receiver artifact | ME73e: WhatsApp-2026-08-16-073720.ips |
| site-2 | `fetchLinkedAndPendingRemoval...currentDeviceList:` | 3 | **RETRACTED** — control (idx2=0) crashes identically; NSNull synthetic receiver artifact | ME73d: WhatsApp-2026-08-16-072737.ips + -072951.ips |
| ME72n lead1 | `processPersistedStanza:...` | (excl.) | TUNNEL-ONLY — completion struct not attacker-set | documented, excluded from bank |

**What remains (non-crash findings):**
- **Static unchecked-index pattern** in WhatsApp's own code (2 helper sites: t7 @0x100337b88,
  companion family `XPluginsGetListLookupDataPair`): `ldrsw` + unshifted `ldr [base, idx]`,
  no bounds check/clamp/modulo. Defense-in-depth gap, **unproven remotely**.
- **Lesson learned:** the in-app synthetic harness cannot prove server-input bugs — it can only
  falsify them. Real proof requires the on-wire rig (Track B).

**Attack-reach classification (rev. 3):**

| Claim | Reach | Status |
|---|---|---|
| t7 zero-click crash | ZERO-CLICK | **RETRACTED** (harness artifact, count-independent) |
| site-1/site-2 one-click crash | ONE-CLICK | **RETRACTED** (synthetic-receiver artifact, index-independent) |
| Zero-click code execution | — | **NEVER PROVEN** (never claimed) |
| Static unchecked-index pattern | (defensive) | STANDS as code finding — not a crash proof |

---

## 2. CRASH BANK — RETRACTED (all 15)

### 2.1 t7 — offline-resume stanza count (10/10) — RETRACTED, artifact

| # | Crash (time) | WhatsApp frame | Verdict |
|---|---|---|---|
| 1–10 | 2026-08-15 04:44–12:10 | 0x3379ec (async thunk) | **ARTIFACT** — count-independent (ME73c count=100 ≡ 0x7FFFFFFF); zeroed instance + async-thunk glue; control never ran |

### 2.2 site-1 — companion-device pending removal (2/2) — RETRACTED, artifact

| # | Crash (time) | WhatsApp frames | Verdict |
|---|---|---|---|
| 1 | 2026-08-15-123349 | `fetchPendingRemoval...:` + `XPluginsGetListLookupDataPair` | **ARTIFACT** — ME73e control (idx2=0) crashes identically; NSNull synthetic receiver |
| 2 | 2026-08-15-124613 | identical | **ARTIFACT** — poison-only run, no control ever ran (v3.1) |

### 2.3 site-2 — linked + pending removal (3/3) — RETRACTED, artifact

| # | Crash (time) | WhatsApp frames | Verdict |
|---|---|---|---|
| 1 | 2026-08-16-021914 | +0x1ca1664 → +0xedd978 (XPluginsGetListLookupDataPair) | **ARTIFACT** — ME73d control (idx2=0) crashes identically |
| 2 | 2026-08-16-022046 | byte-identical | **ARTIFACT** — same |
| 3 | 2026-08-16-022223 | byte-identical | **ARTIFACT** — same |

### 2.4 Excluded (never counted)

| Crash | Reason |
|---|---|
| 132741 | nil-table artifact (v8b era) |
| 131056 / 131354 / 132029 / 132538 / 135350 / 135619 | app-self WALog aborts — zero dylib frames |
| 074856 | ME72n-era lead1 (tunnel-only) |

---

## 3. HONEST METHODOLOGY LESSON (why the harness cannot prove)

1. **Synthetic receivers lie.** Calling a WhatsApp method with `self` = our own NSArray (or a
   zeroed `class_createInstance`) guarantees method-body behavior on garbage — the frames are
   WhatsApp's, but the object graph is entirely ours. Any crash produced this way is
   **uninterpretable** without a control that returns normally.
2. **Controls are mandatory.** Every run needs an unpoisoned call that RETURNS on the same
   receiver. t7's control never ran; site-2's control was skipped ("NSNull entries would not
   respond... and crash the control" — i.e., the harness author predicted the artifact); site-1
   was poison-only. All three were unfalsifiable until the ladder ran.
3. **The ladder is the arbiter.** Index ladders {0, 5, 100, 1k, 100k, 200k, 0x7FFFFFFF} with
   per-step logging: controls crash → artifact; controls pass + high index crashes → real OOB.
   Both t8 sites failed at control step 1; t7 failed the count-independence test.
4. **Static patterns ≠ vulnerabilities.** `ldr [base, idx]` without a bounds check is a
   *suspicion*, not a finding. Proving it needs the index to be attacker-controlled AND the
   crash/read to occur with a realistic value in the real object graph.

---

## 4. QA VERDICT (static audit — DEFENSIVE, unproven dynamically)

The static audits remain valid as **code findings**:
1. t7 helper @0x100337b88: `ldrsw x8,[x8,#0x10]` → `ldr x25,[x21,x8]` — raw offset, no check.
2. Companion helper `XPluginsGetListLookupDataPair`: same unchecked shape.
3. Recommended defensive fix regardless: clamp/validate server-supplied counts and device-list
   indices immediately after receipt.

**But: NO dynamic proof exists. Do NOT ship this as a vulnerability claim.**

---

## 5. EVIDENCE INDEX (repo: khalifa348/wafix, main)

- `evidence/me73e_control/` — **NEW**: ME73d control crash (072737, 072951), ME73e control crash
  (073720), ME73e marker — the falsification evidence for site-1/site-2
- `evidence/v10_site2/` — the ORIGINAL site-2 claims (now retracted; marker contains
  `[ctrl] SKIPPED — synthetic slot`)
- `evidence/me73_crash_proof.md` — t7 proof (now retracted)
- `evidence/t8_count_verdict.txt` — static QA audit (defensive value only)
- `evidence/t7_unguarded_sites.txt` — 18 exact-shape candidate sites (static)
- Crash originals: `zdl_stage/me73_crashes/`, `me73b_crashes/`, `me73c_crashes/`, `me73d_crashes/`, `me73e_crashes/`
- Builds: `me73d.m` (site-2 ladder), `me73e.m` (site-1 ladder), both with per-step logging

---

## 6. NEXT STEPS (open items)

1. **Track B — on-wire rig (the ONLY proof path).** Real server → realistic count / device-list
   → pristine app with a REAL initialized storage-manager instance. Blocked on fresh number:
   T-Mobile Trial eSIM (free 30-day real US number) → Etisalat $8 prepaid SIM (guaranteed) →
   SMSPool ~$0.10–0.50 rental.
2. **Scan remaining XMPP handlers** (18 static candidate sites) — but results are **static
   leads only** until the on-wire rig exists.
3. **Info-leak assessment** — only meaningful on-wire.
4. If a fresh number is never available, the WhatsApp lane's honest deliverable is the
   **defensive code findings + harness-methodology writeup** (both valuable to a security team).
