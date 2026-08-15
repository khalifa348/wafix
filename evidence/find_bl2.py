"""find_bl2.py — find all BL/B references to a target VA in __TEXT (NEW 26.24.72).
Usage: find_bl2.py <target_va>
"""
import struct, sys

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
BASE = 0x100000000
target = int(sys.argv[1], 16)

with open(PATH, 'rb') as f:
    d = f.read()

# find __TEXT section range via mach header
magic = struct.unpack('<I', d[:4])[0]
ncmds = struct.unpack('<I', d[16:20])[0]
p = 32
text_off = text_size = None
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack('<II', d[p:p+8])
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = d[p+8:p+24].rstrip(b'\x00').decode()
        if segname == '__TEXT':
            text_vm = struct.unpack('<Q', d[p+0x18:p+0x20])[0]
            text_off = struct.unpack('<Q', d[p+0x28:p+0x30])[0]  # fileoff
            text_size = struct.unpack('<Q', d[p+0x30:p+0x38])[0]  # filesize
    p += cmdsize
print(f'__TEXT fileoff={text_off:#x} size={text_size:#x}')

hits = []
for off in range(text_off, text_off + text_size - 4, 4):
    insn = struct.unpack('<I', d[off:off+4])[0]
    # BL imm26 (opcode 0x94000000) or B imm26 (0x14000000)
    if (insn & 0xFC000000) in (0x94000000, 0x14000000):
        imm = insn & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        va = (BASE + off) + imm * 4
        if va == target:
            hits.append(BASE + off)
print(f'BL/B calls to {target:#x}: {len(hits)}')
for h in hits[:20]:
    print(f'  caller @ {h:#x}')
