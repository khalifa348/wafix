"""find_caller_sel.py — find code refs to a selector's selref slot (v3 logic).
Usage: find_caller_sel.py <selector-substring>
Scans __TEXT for ADRP+ADD/LDR sequences targeting the selref slot of the
selector whose name contains the substring, then prints the enclosing
function's disassembly window around each ref.
"""
import struct, bisect, sys, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
data = open(PATH, 'rb').read()
SUB = sys.argv[1].encode()

# ---- section table ----
sects = []
ncmds, = struct.unpack_from('<I', data, 16)
off = 32
for _ in range(ncmds):
    cmd, csize = struct.unpack_from('<II', data, off)
    if cmd == 0x19:
        nsects, = struct.unpack_from('<I', data, off+64)
        so = off + 72
        for _ in range(nsects):
            sname = data[so:so+16].rstrip(b'\x00').decode()
            saddr, ssize = struct.unpack_from('<QQ', data, so+0x20)
            soff = struct.unpack_from('<I', data, so+0x30)[0]
            sects.append((saddr, ssize, soff, sname))
            so += 80
    off += csize
sects.sort()
vmaddrs = [s[0] for s in sects]

def vm_to_file(va):
    i = bisect.bisect_right(vmaddrs, va) - 1
    if i < 0: return None
    va0, sz, fo, _ = sects[i]
    return fo + (va - va0) if va < va0 + sz else None

def sec_of(name):
    for saddr, ssize, soff, sname in sects:
        if sname == name:
            return saddr, ssize, soff
    return None

# ---- find selector string + selref slots ----
methname = sec_of('__objc_methname')
sel_va = None
if methname:
    mva0, msz, mfo = methname
    for i in range(mfo, mfo + msz):
        if data[i:i+len(SUB)] == SUB:
            # back up to string start
            s = i
            while s > mfo and data[s-1] != 0:
                s -= 1
            sel_va = mva0 + (s - mfo)
            break
print(f'selector "{SUB.decode()}" @ {sel_va:#x}' if sel_va else f'selector "{SUB.decode()}" NOT FOUND')
if not sel_va:
    sys.exit(1)

# selref section
selrefs = sec_of('__objc_selrefs')
slots = []
if selrefs:
    sva0, ssz, sfo = selrefs
    for i in range(0, ssz, 8):
        raw = struct.unpack_from('<Q', data, sfo + i)[0]
        if (raw & 0xFFFFFFFFF) == sel_va:
            slots.append(sva0 + i)
print(f'selref slots: {len(slots)}')
for s in slots:
    print(f'  slot {s:#x}')

if not slots:
    sys.exit(0)

# ---- scan __TEXT for ADRP targeting page of a slot, then ADD/LDR to slot ----
text = sec_of('__text')
if not text:
    sys.exit(0)
tva0, tsz, tfo = text
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

# chunked disasm; look for adrp xN, #PAGE followed within 4 insns by add xM, xN, #PAGEOFF
# or ldr xM, [xN, #PAGEOFF] where target == slot
found = []
chunk = 4 << 20
for base in range(tva0, tva0 + tsz, chunk):
    fo = tfo + (base - tva0)
    code = data[fo:fo+chunk]
    insns = list(md.disasm(code, base))
    n = len(insns)
    for i, ins in enumerate(insns):
        if ins.mnemonic != 'adrp':
            continue
        m = re.match(r'x(\d+), #0x([0-9a-f]+)$', ins.op_str)
        if not m:
            continue
        reg = int(m.group(1))
        page = int(m.group(2), 16)
        for j in range(1, 5):
            k = i + j
            if k >= n:
                break
            nxt = insns[k]
            if nxt.mnemonic in ('add', 'ldr') and f'x{reg}' in nxt.op_str:
                m2 = re.match(r'x\d+, \[?x\d+, #(0x[0-9a-f]+)\]?$', nxt.op_str)
                if nxt.mnemonic == 'add':
                    m2 = re.match(r'x(\d+), x\d+, #(0x[0-9a-f]+)$', nxt.op_str)
                    if m2:
                        tgt = page + int(m2.group(2), 16)
                        if tgt in slots:
                            found.append((ins.address, 'add', tgt))
                else:
                    m2 = re.match(r'x(\d+), \[x\d+, #(0x[0-9a-f]+)\]', nxt.op_str)
                    if m2:
                        tgt = page + int(m2.group(2), 16)
                        if tgt in slots:
                            found.append((ins.address, 'ldr', tgt))
print(f'code refs: {len(found)}')
for addr, kind, slot in found:
    print(f'  {addr:#x} ({kind}) -> slot {slot:#x}')
    # print window
    win = [x for x in insns if addr - 0x40 <= x.address <= addr + 0x80]
    for x in win:
        print(f'    {x.address:#x}: {x.mnemonic:8s} {x.op_str}')
