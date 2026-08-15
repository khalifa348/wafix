#!/usr/bin/env python
"""t8 scan: find unchecked index sites in WhatsApp binary (own test build).
Pattern family: ldrsw xN,[xM,#imm] followed (within a few instrs) by
ldr xK,[xBASE,xN] with NO bounds check between. Plus selector dump."""
import glob, struct, re, sys
from capstone import *
from capstone.arm64 import *

BIN = None
for p in glob.glob(r"C:\Users\User\zdl_stage\t8_work\Payload\**\WhatsApp", recursive=True):
    BIN = p; break
if not BIN:
    sys.exit("WhatsApp binary not found under t8_work/Payload")
print("Binary:", BIN)

data = open(BIN, "rb").read()
BASE = 0x100000000
print("File size: %.1f MB" % (len(data)/1e6))

# --- 1) selectors of interest ---
pats = [b"Count", b"Stanza", b"Resume", b"Batch", b"Chunk", b"Offset", b"Index", b"Length"]
found = {}
for pat in pats:
    for m in re.finditer(re.escape(pat), data):
        s = m.start()
        # crude selector check: printable run containing pat
        lo = max(0, s-40); hi = min(len(data), s+40)
        ctx = data[lo:hi]
        if all(32 <= b < 127 or b in (0,) for b in ctx):
            # extract the printable run
            run = re.search(rb"[ -~]*" + re.escape(pat) + rb"[ -~]*", ctx)
            if run:
                found.setdefault(pat.decode(), set()).add(run.group(0).decode(errors="replace"))
print("\n=== selector keywords found ===")
for k, v in found.items():
    print(f"\n[{k}] {len(v)} unique strings; sample:")
    for s in sorted(v)[:12]:
        print("   ", s)

# --- 2) pattern scan: ldrsw xN,[xM,#imm] ... ldr xK,[xL,xN] ---
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
md.skipdata = True  # keep going across padding/gaps instead of stopping

# find __text section (code) file range
mh = struct.unpack("<I", data[:4])[0]
assert mh == 0xFEEDFACF, "not a 64-bit mach-o"
ncmds, = struct.unpack("<I", data[16:20])
off = 32
text_fileoff = text_filesize = text_addr = None
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack("<II", data[off:off+8])
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[off+8:off+24].split(b"\0")[0]
        nsects, = struct.unpack("<I", data[off+64:off+68])
        if segname == b"__TEXT":
            for s in range(nsects):
                so = off + 72 + s*80
                sectname = data[so:so+16].split(b"\0")[0]
                if sectname == b"__text":
                    text_addr, = struct.unpack("<Q", data[so+32:so+40])
                    text_fileoff, = struct.unpack("<I", data[so+48:so+52])
                    text_filesize, = struct.unpack("<Q", data[so+40:so+48])
                    print("\n__text addr=%x fileoff=%x size=%x" % (text_addr, text_fileoff, text_filesize))
    off += cmdsize

hits = []
TEXT = data[text_fileoff:text_fileoff+text_filesize]
for i in md.disasm(TEXT, text_addr):
    if i.mnemonic == "ldrsw":
        # find the register loaded
        src = i.op_str  # e.g. "x8, [x8, #0x10]"
        m = re.search(r"\[x(\d+), #(-?(?:0x[0-9a-f]+|\d+))\]", src)
        if not m: continue
        reg = "x" + m.group(1)
        # look ahead up to 6 instructions for ldr using reg as index
        nxt = list(md.disasm(TEXT[i.address-text_addr+ i.size: i.address-text_addr + i.size + 24], i.address + i.size))
        for j, ins in enumerate(nxt[:6]):
            if ins.mnemonic == "ldr" and re.search(r"\[x\d+, " + reg + r"\]", ins.op_str):
                # bounds check between? look for cmp/tbz/cbnz on reg
                between = nxt[:j]
                bc = any(x.mnemonic in ("cmp","cmn","tbz","tbnz","cbnz","cbz","csel") and reg in x.op_str for x in between)
                hits.append((i.address, ins.address, bc, i.op_str, ins.op_str))
                break

print(f"\n=== ldrsw->ldr index sites: {len(hits)} ===")
for addr, ldr_addr, bc, op1, op2 in hits:
    flag = "NO-BOUNDS-CHECK" if not bc else "has check"
    print(f"  0x{addr:X}  {op1:16s} -> 0x{ldr_addr:X}  {op2:20s} [{flag}]")

# save ranked candidates (no-bounds first)
with open(r"C:\Users\User\zdl_stage\t8_scan_candidates.txt", "w") as f:
    f.write("t8 scan candidates (own test build 26.24.72, base 0x100000000)\n")
    f.write("pattern: ldrsw xN,[xM,#imm] then ldr xK,[xL,xN] (unshifted index)\n\n")
    f.write("known-proven site: 0x100337bc8 ldrsw x8,[x8,#0x10] -> 0x100337bcc ldr x25,[x21,x8] (crash on-device)\n\n")
    for addr, ldr_addr, bc, op1, op2 in hits:
        f.write(f"0x{addr:X} {op1} -> 0x{ldr_addr:X} {op2} {'NO-BOUNDS-CHECK' if not bc else 'has-check'}\n")
print("\nSaved to zdl_stage/t8_scan_candidates.txt")
