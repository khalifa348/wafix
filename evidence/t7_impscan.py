"""t7_impscan.py — scan resolved stanza IMPs for ME72n-class bug:
ldrsw xN,[xM] (no bounds check) followed <=6 insns later by a register-indexed
table load (ldr/ldrb/ldrh/ldrsw/ldrsb with xN as index), no cmp/tst/cbz/cbnz on
xN in between. Output candidates + mini context.
"""
import struct, bisect, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
data = open(PATH, 'rb').read()

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

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

def get_insns(va, length=0x400):
    fo = vm_to_file(va)
    if fo is None:
        return []
    return list(md.disasm(data[fo:fo+length], va))

def func_insns(imp_va):
    """Disassemble from IMP, stopping at first ret/tail-jump (function boundary).
    Handles Swift async thunks: if first insns are bl-bl-bl + b stub, follow the
    b target chain once to the real body."""
    insns = get_insns(imp_va, 0x40)
    # Swift async wrapper: starts stp x29,x30, then several bl, ends b stub
    if len(insns) > 3 and insns[-1].mnemonic == 'b' and 'bl' in [i.mnemonic for i in insns[:4]]:
        target = insns[-1].op_str.strip('#')
        try:
            tva = int(target, 16)
        except ValueError:
            pass
        else:
            tfo = vm_to_file(tva)
            if tfo is not None:
                return get_insns(tva, 0x400)
    return insns

def scan_imp(imp_va, name):
    """Scan the FUNCTION BODY (not a fixed window) for the pattern."""
    insns = func_insns(imp_va)
    hits = []
    n = len(insns)
    for i, ins in enumerate(insns):
        m = ins.mnemonic
        if m != 'ldrsw':
            continue
        om = re.match(r'x(\d+), \[x(\d+)(?:, #(?:0x)?[0-9a-fA-F]+)?\]', ins.op_str)
        if not om:
            continue
        idx = int(om.group(1))
        for j in range(1, 7):
            k = i + j
            if k >= n:
                break
            nxt = insns[k]
            if nxt.mnemonic in ('cmp', 'tst', 'cbz', 'cbnz', 'subs', 'ands') and f'x{idx}' in nxt.op_str:
                break
            if nxt.mnemonic.startswith('b.') and f'x{idx}' in nxt.op_str:
                break
            if nxt.mnemonic in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsb', 'ldur', 'ldurb'):
                om2 = re.match(r'x(\d+), \[x(\d+), x(\d+)\]', nxt.op_str)
                if om2 and om2.group(3) == str(idx):
                    hits.append((ins.address, j, ins.op_str, nxt.address, nxt.op_str))
                    break
    return hits

# load IMP list from stanza_imps_out.txt
imps = {}
for line in open('stanza_imps_out.txt', encoding='utf-8', errors='replace'):
    line = line.strip()
    if not line or 'total unique' in line:
        continue
    try:
        addr_s, rest = line.split(' ', 1)
        imp_va = int(addr_s, 16)
        rest = rest.strip()
        # rest: [cat] name
        if rest.startswith('['):
            _, _, name = rest.partition('] ')
        else:
            name = rest
        imps.setdefault(imp_va, set()).add(name)
    except Exception:
        pass

print(f'IMP count: {len(imps)}')
total_hits = 0
out = []
for imp_va, names in sorted(imps.items()):
    hits = scan_imp(imp_va, next(iter(names)))
    if hits:
        total_hits += len(hits)
        out.append((imp_va, names, hits))

print(f'IMPs with unchecked ldrsw->table hits: {len(out)}')
for imp_va, names, hits in out:
    nm = next(iter(names))
    for h in hits:
        print(f'IMP {imp_va:#x} {nm}')
        print(f'   {h[0]:#x}: {h[2]}  ->  +{h[1]} insn: {h[3]:#x}: {h[4]}')
