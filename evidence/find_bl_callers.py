"""find_bl_callers.py — find all BL/B callers of a target address in __TEXT."""
import struct, bisect, sys, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
data = open(PATH, 'rb').read()
TARGET = int(sys.argv[1], 16)
WINDOW = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x80

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

text = sec_of('__text')
tva0, tsz, tfo = text
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

found = []
chunk = 4 << 20
for base in range(tva0, tva0 + tsz, chunk):
    fo = tfo + (base - tva0)
    code = data[fo:fo+chunk]
    insns = list(md.disasm(code, base))
    for ins in insns:
        if ins.mnemonic in ('bl', 'b') and ins.op_str.startswith('#'):
            try:
                tgt = int(ins.op_str[1:], 16)
            except ValueError:
                continue
            if tgt == TARGET:
                found.append(ins.address)

print(f'callers of {TARGET:#x}: {len(found)}')
for addr in found:
    # find function start: scan back for prologue
    fstart = None
    i = 0
    back = []
    for base2 in range(addr - 0x100, addr, 4):
        fo2 = vm_to_file(base2)
        if fo2 is not None:
            w = struct.unpack_from('<I', data, fo2)[0]
            if (w & 0xFFC003FF) == 0xA9800000 or w in (0xD503233F,):  # stp x29,x30 or pacibsp
                fstart = base2
    print(f'  caller at {addr:#x}' + (f' (func start ~{fstart:#x})' if fstart else ''))
    # window
    fo2 = vm_to_file(addr - 0x40)
    if fo2 is not None:
        for x in md.disasm(data[fo2:fo2+WINDOW], addr - 0x40):
            print(f'    {x.address:#x}: {x.mnemonic:8s} {x.op_str}')
    print()
