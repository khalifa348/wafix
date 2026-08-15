"""resolve_bind.py — resolve dyld bind opcodes for a GOT slot address.
Usage: resolve_bind.py <vm-address-of-slot> <vm-address-of-thunk-b-target>
Parses LC_DYLD_INFO_ONLY bind opcodes to find which symbol binds the slot.
"""
import struct, sys

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
data = open(PATH, 'rb').read()
SLOT = int(sys.argv[1], 16)

# load commands
ncmds, = struct.unpack_from('<I', data, 16)
off = 32
dyld = None
syms = None
strs = None
text_va = None
for _ in range(ncmds):
    cmd, csize = struct.unpack_from('<II', data, off)
    if cmd == 0x2:  # LC_SYMTAB
        symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', data, off + 8)
        syms = (symoff, nsyms)
        strs = (stroff, strsize)
    if cmd == 0x1:  # LC_SEGMENT_64
        nsects, = struct.unpack_from('<I', data, off + 64)
        seg_va, seg_fo, seg_sz = struct.unpack_from('<QQQ', data, off + 0x18)
        so = off + 72
        for _ in range(nsects):
            sname = data[so:so+16].rstrip(b'\x00').decode()
            saddr, ssize = struct.unpack_from('<QQ', data, so+0x20)
            soff = struct.unpack_from('<I', data, so+0x30)[0]
            if sname == '__text':
                text_va = saddr
            so += 80
    if cmd == 0x80000022:  # LC_DYLD_INFO_ONLY
        dyld = struct.unpack_from('<16I', data, off + 8)
    off += csize

if not dyld:
    print('no dyld info')
    sys.exit(1)
(_, _, _, _, _, _, _, _, bind_off, bind_sz, _, _, _, _, _, _) = dyld
symoff, nsyms = syms
stroff, strsize = strs
bind = data[bind_off:bind_off+bind_sz]

BIND_OPCODE_MASK = 0xF0
BIND_IMM = 0x0F
BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_DO_BIND = 0x40
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0x50
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0x60
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0x70
BIND_OPCODE_THREADED = 0x80
BIND_SUBOPCODE_THREADED_APPLY = 0x00
BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB = 0x01
BIND_SUBOPCODE_THREADED_APPLY_TO_NON_POINTER_BIND = 0x02

def read_uleb(buf, i):
    result = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, i

# walk binds
i = 0
addr = 0x0  # starts at 0, segment-relative (first segment usually __TEXT at 0)
dylib_ord = 0
threaded = False
results = []
while i < len(bind):
    op = bind[i]
    code = op & BIND_OPCODE_MASK
    imm = op & BIND_IMM
    i += 1
    if code == BIND_OPCODE_DONE:
        break
    elif code == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        dylib_ord = imm
    elif code == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
        dylib_ord, i = read_uleb(bind, i)
    elif code == BIND_OPCODE_DO_BIND:
        if addr == SLOT:
            results.append((dylib_ord, None, addr))
        addr += 8
    elif code == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        if addr == SLOT:
            results.append((dylib_ord, None, addr))
        v, i = read_uleb(bind, i)
        addr += v + 8
    elif code == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        if addr == SLOT:
            results.append((dylib_ord, None, addr))
        addr += imm * 8 + 8
    elif code == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        count, i = read_uleb(bind, i)
        skip, i = read_uleb(bind, i)
        for _ in range(count):
            if addr == SLOT:
                results.append((dylib_ord, None, addr))
            addr += skip + 8
    elif code == BIND_OPCODE_THREADED:
        sub = imm
        if sub == BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
            v, i = read_uleb(bind, i)
        elif sub == BIND_SUBOPCODE_THREADED_APPLY:
            # threaded bind: each bind is the slot content itself; the target
            # symbol ordinal is in the pointer's low bits. Skip (we handle via
            # raw slot decode elsewhere).
            threaded = True
        elif sub == BIND_SUBOPCODE_THREADED_APPLY_TO_NON_POINTER_BIND:
            pass
    else:
        pass  # skip other ops (set segment, set symbol, set type, etc.)

print(f'slot {SLOT:#x}: direct bind entries: {results}')
if threaded:
    print('note: threaded bind present — target derived from slot raw value')
# If threaded: raw slot value 0x8010000000000015 → bit63=1 (bind), ordinal bits?
raw = struct.unpack_from('<Q', data, 0)[0]  # placeholder
