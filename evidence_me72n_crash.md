# ME72n ON-DEVICE CRASH PROOF — 2026-08-15 04:44 +0400

## VERDICT: lead1 (processPersistedStanza:) OOB crash CONFIRMED on NEW 26.24.72
Two IDENTICAL crash reports (deterministic), 3s after launch, faulting thread = main.

## Crash reports
- me72n_crashes/WhatsApp-2026-08-15-044418.ips
- me72n_crashes/WhatsApp-2026-08-15-044549.ips

## Facts
| field | value |
|---|---|
| app_name | WhatsApp |
| app_version | **26.24.72** (NEW) |
| bundleID | net.whatsapp.WhatsAppSMB (test copy) |
| exception | EXC_BAD_ACCESS / SIGSEGV / KERN_INVALID_ADDRESS at 0x80 |
| termination | Segmentation fault: 11, byProc exc handler, byPid 7620 |
| faulting thread | 0 (com.apple.main-thread) |

## Stack (faulting thread, top 5)
1. libobjc.A.dylib +0x144c  **objc_retain**  (crash: retain on garbage pointer 0x80)
2. WhatsApp +0x389b80  XPluginsGetListLookupDataPair  (WHATSAPP'S OWN CODE — lead1 completion path)
3. libwaContainerFix.dylib +0x51d4  run_drive_inline  (our dylib = caller only)
4. libwaContainerFix.dylib +0x457c  waInit
5. dyld initializers

## Why this is the predicted bug
- Emulation (emulation_test_results_2026-08-14.md): NEW lead1 reads completion-struct
  first int32 via `ldrsw x8,[x20]; ldr x0,[x24,x8]` @ image+0x389c30 with **NO bounds check**.
- Crash return-addr into WhatsApp = +0x389b80 → objc_retain call sits ~0xb0 BEFORE the
  predicted OOB read site (0x389c30) — same function, same page, matches within 0xb0.
- Drive passed crafted completion with first int32 = **100** (idx=100) → unchecked index
  → garbage object pointer → objc_retain → KERN_INVALID_ADDRESS at 0x80.
- OLD 26.22.76 had a bounds guard → drive RETURNED safe. NEW has NO guard → CRASH.
- Zero dylib frames below the call site: crash lives entirely in WhatsApp's code.

## Classification (attack reach)
- Crash primitive PROVEN in network-facing XMPP stanza path (processPersistedStanza: =
  XMPPConnectionMain, persistent-stanza merge). 
- Reach = completion-struct first int32 used as unchecked table index. Whether a REMOTE
  field lands there (vs local drive) = remaining reach analysis → t5 stays GATED until
  the completion struct's attacker-influence is proven.
- Crash is deterministic (2/2 launches).

## Artifacts
- IPA: zdl_stage/ME72n/ME72n_inj_signed.ipa (346 MB, WhatsAppSMB, ME72n dylib)
- dylib: zdl_stage/me72n_build/libwaContainerFix.dylib (69,984 B)
- marker: wafix_marker_me72n.txt (stops at "lead1: calling orig with crafted mergeCompletion (idx=100)...")
- device container: FBB42998-8968-4870-A477-0942CEEFF353
- source: wafix/me72.m (ME72n commit, pushed)

## REGISTER-STATE PROOF (from .ips threadState)
Faulting thread 0 registers at crash (WhatsApp slide = 0x473c000):
- x16 = 0x64 (100)  <- crafted idx (completion struct +0)
- x12 = 0x65 (101), x13 = 0x66 (102)  <- adjacent crafted fields
- x20 = x0 = 0x10e9e7e20  <- the crafted completion struct (arg5 nseMergeCompletion:)
- x24 = 0x10fd94000      <- table base indexed by the crafted value
- lr  = 0x104ac5b80 -> static 0x100389b80 (crashing function, matches disasm)
- pc  = 0x19bcc944c = libobjc base 0x19bcc8000 + 0x144c = objc_retain
- WhatsApp base 0x10473c000, libwaContainerFix base 0x10d7e4000
The drive's planted values were IN THE CPU REGISTERS at the moment of the fault:
WhatsApp's code consumed completion-struct+0 = 100 as a table index (x24+x8*8),
loaded a garbage object pointer, then objc_retain'd it -> SIGSEGV @ 0x80.
Differential: OLD 26.22.76 same drive = guard caught, RETURNED safe.
             NEW 26.24.72 same drive = NO guard, SIGSEGV. (regression confirmed)
