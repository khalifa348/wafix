"""disasm_func.py — disassemble a function region around a vmaddr."""
import struct, bisect, sys
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

start = int(sys.argv[1], 16)
length = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x400
fo = vm_to_file(start)
if fo is None:
    print('unmapped')
    sys.exit(1)
for ins in md.disasm(data[fo:fo+length], start):
    print(f'{ins.address:#x}: {ins.mnemonic:8s} {ins.op_str}')
