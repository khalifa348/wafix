# ME72n lead1 — Reach Analysis (t5) — 2026-08-15

## Verdict
**Crash: PROVEN on-device (deterministic, 2/2 .ips). Reach: the completion struct's
first int32 is NOT directly attacker-controlled — it is constructed by WhatsApp's
own NSE-merge machinery. Remote input lands in the *stanza* (arg2), NOT in the
completion struct (arg5). → classify: LOCAL/DRIVE-driven (tunnel), NOT zero-click.**

## Caller chain (NEW 26.24.72, base 0x100000000)

```
function A (prologue @0x10038941c, ObjC method via msgSend — no direct BL callers)
  arg4 (x4) = completion struct            ← passed DOWN from higher NSE-merge caller
  mov x20, x4                              @0x100389428
  ...
  str x20, [sp,#0x60]                      @0x1003896dc  (completion saved)
  loop @0x100389930 over stanza queue (x23=idx, x26=count):
    ldr x24, [x8, x23, lsl #3]             @0x100389948  (stanza i)
    ...
    mov  x3, x19                           @0x10038998c
    ldr  w4, [sp,#0x6c]                    @0x100389990  (isFromDeferredNSEMerge)
    ldr  x5, [sp,#0x60]                    @0x100389994  (completion = arg5)
    bl   #0x1051604cc                      @0x100389998  → objc_msgSend(processPersistedStanza:...)
    add x23,x23,#1; cmp x23,x26; b.lo      loop

function B = processPersistedStanza:inPersistentStanzaQueue:isFromDeferredNSEMerge:nseMergeCompletion:
  (prologue @0x100389b5c, IMP; dispatched via the selref stub at 0x1051604cc)
  mov x20, x5                              @0x100389b68  (completion → x20)
  ...
  ldrsw x8, [x20]                          @0x100389c30  (completion+0 int32 = OUR 100)
  ldr   x0, [x24, x8]                      @0x100389c34  (OOB table read, NO bounds check)
  bl    ...                                @0x100389c38  (objc_retain on garbage → SIGSEGV @0x80)
```

## Key facts
- The completion struct is **arg5 of processPersistedStanza:...** — passed down from
  a higher NSE-merge caller (function A receives it as arg4). It is NOT derived from
  the stanza bytes (arg2).
- The stanza (remote input) flows into arg2/arg3; the completion struct is
  constructed by WhatsApp's own merge machinery (opaque C struct, first int32 used
  as table index).
- Our drive FORGES the completion struct (idx=100) — this is a dylib-driven
  trigger, exactly the "dylib drives, app faults" model. A remote attacker cannot
  set completion+0 directly without a separate corruption primitive.
- **OLD 26.22.76 differential**: exact instruction sequence `ldrsw x8,[x20]; ldr x0,[x24,x8]`
  exists at OLD 0x103c565bc BUT in a DIFFERENT function (x20 there = global-derived,
  not arg5) → OLD's processPersistedStanza does NOT contain this unchecked pattern.
  Consistent with ME72m on-device control: OLD lead1 RETURNED (guard present).
  (OLD IMP exact site not statically resolved — classlist walk failed on arm64e
  relative method lists; byte-signature differential stands.)

## Reach classification
| Attack reach | Status |
|---|---|
| zero-click (remote) | ❌ NOT reachable — completion struct not attacker-set |
| one-click (remote) | ❌ same — no remote path into completion+0 |
| tunnel / local drive | ✅ PROVEN — deterministic crash 2/2, registers match |

## Tooling lessons (this round)
- iOS 26 binaries use **dyld chained fixups**: __objc_selrefs slots on disk are NOT
  raw pointers. Low 36 bits of each slot = target VM address (high 16 = next field).
  → resolve selref by `(val & 0xFFFFFFFFF)`.
- Mach-O section offset field is **4 bytes at +0x30** (not 8) — earlier reads were garbage.
- `ldrsw x8,[x20]` encoding = 0xB9800288 (not 0xB8800288 — size bit).
- Reach scan recipe (find_callers.py): ADRP+ADD/LDR into selref range → dedupe slots →
  chain-decode slot targets → match selector → disasm around code refs → find BL/B
  into the stub → the stub is the objc_msgSend dispatch for that selector.
- old_diff.py: __objc_classlist walk with relative method lists (arm64e) needs
  entsize&0x80000000 handling — first version found 0 IMPs; byte-signature matching
  on crash-site sequences is the pragmatic fallback.

## Status
- t5 (reach analysis): COMPLETE — classification: tunnel/local only.
- t5 delivery re-arm: NOT justified for this lead (not remote-reachable).
- Next: keep hunting leads where remote data DIRECTLY drives the fault (stanza→index),
  or a second primitive to corrupt the completion struct.
