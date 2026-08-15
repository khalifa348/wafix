"""t7 scan: enumerate UNCHECKED ldrsw xN,[xM] -> ldr x0,[xT, xN] table-index sites
in NEW 26.24.72 (same bug class as ME72n crash site @0x100389c30).
For each ldrsw-immediate, look ahead <=6 insns for a register-offset load using
the same index reg; flag GUARDED if a cmp/tst/cbz/cbnz/b.cond/csel touches idx
in between. Output unguarded sites with function-context window.
"""
import struct, sys
import capstone

NEW = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
BASE = 0x100000000
data = open(NEW, 'rb').read()

# ---- locate __TEXT/__text ----
ncmds, = struct.unpack_from('<I', data, 16)
off = 32
text = None
for _ in range(ncmds):
    cmd, csize = struct.unpack_from('<II', data, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        nsects, = struct.unpack_from('<I', data, off+64)
        so = off + 72
        for _s in range(nsects):
            sname = data[so:so+16].rstrip(b'\x00').decode()
            saddr, ssize = struct.unpack_from('<QQ', data, so+0x20)
            soff = struct.unpack_from('<I', data, so+0x30)[0]
            if sname == '__text':
                text = (soff, ssize, saddr)
            so += 80
    off += csize
assert text, '__text not found'
soff, ssize, saddr = text
print(f'__text: fileoff={soff:#x} size={ssize:#x} vm={saddr:#x}')

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

def reg_of(opstr, prefix):
    """extract register number from op_str like 'x8' or 'x8, ...'"""
    import re
    m = re.match(rf'^{prefix}(\d+)', opstr)
    return int(m.group(1)) if m else None

import re
sites = []
CHUNK = 1 << 20
for base_off in range(0, ssize, CHUNK):
    chunk = data[soff+base_off : soff+base_off+CHUNK]
    pc0 = saddr + base_off
    insns = list(md.disasm(chunk, pc0))
    for i, ins in enumerate(insns):
        if ins.mnemonic != 'ldrsw':
            continue
        m = re.match(r'^x(\d+), \[x(\d+)(?:, #(0x[0-9a-f]+|\d+))?\]$', ins.op_str)
        if not m:
            continue  # only immediate form ldrsw xN,[xM]
        idx = int(m.group(1))
        # look ahead up to 6 insns for register-offset load using idx
        window = insns[i+1:i+7]
        guarded = False
        table_site = None
        for j, w in enumerate(window):
            ops = w.op_str
            # check for guard touching idx
            if (w.mnemonic in ('cmp','tst','subs','ands') and
                re.search(rf'\bx{idx}\b', ops)) or \
               (w.mnemonic in ('cbz','cbnz','b.eq','b.ne','b.lo','b.hs','b.ge','b.lt','csel','cset','tbnz','tbz') and
                re.search(rf'\bx{idx}\b', ops)):
                guarded = True
            # register-offset load: 'ldr x0, [x24, x8]' or ldrb/ldrh/ldrsw
            if w.mnemonic in ('ldr','ldrb','ldrh','ldrsw','ldrsb','ldrsh') and \
               re.search(rf'\[x\d+, x{idx}\]', ops):
                table_site = (j, w.mnemonic, w.op_str, w.address)
                break
        if table_site:
            sites.append((ins.address, idx, ins.op_str, guarded, table_site))

print(f'total ldrsw->table sites: {len(sites)}')
print(f'UNGUARDED: {sum(1 for s in sites if not s[3])}')
print(f'guarded:   {sum(1 for s in sites if s[3])}')

# ---- function context for unguarded sites ----
def find_func_start(pc):
    """scan back up to 0x300 bytes for stp x29,x30,[sp,#-N]! or sub sp prologue"""
    foff = (pc - saddr) & ~0x3
    lo = max(0, foff - 0x300)
    for b in range(foff-4, lo, -4):
        w = struct.unpack_from('<I', data, soff + b)[0]
        # stp x29,x30,[sp,#-imm]! = 0xA9800000 | ... ; or sub sp,sp,#imm = 0xD10003FF pattern
        if (w & 0xFFC003E0) == 0xA98003E0:  # stp x29,x30,[sp,#-imm]!
            return saddr + b
        if (w & 0xFF8003FF) == 0xD10003FF:  # sub sp, sp, #imm
            return saddr + b
    return None

with open('t7_unguarded_sites.txt', 'w') as f:
    for pc, idx, ldrsw, guarded, (j, mn, ops, taddr) in sites:
        if guarded:
            continue
        fs = find_func_start(pc)
        fs_str = f'{fs:#x}' if fs is not None else '?'
        f.write(f'SITE pc={pc:#x} idx=x{idx} {ldrsw} -> {j+1}instr later: {mn} {ops} @{taddr:#x} func_start={fs_str}\n')
print('wrote t7_unguarded_sites.txt')
