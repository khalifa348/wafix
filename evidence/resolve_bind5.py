"""resolve_bind5.py — resolve threaded-bind ordinal via LC_SYMTAB nlist.
Usage: resolve_bind5.py <ordinal_hex>
"""
import struct, sys

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
data = open(PATH, 'rb').read()
ORD = int(sys.argv[1], 16)

ncmds, = struct.unpack_from('<I', data, 16)
off = 32
syms = None
strs = None
for _ in range(ncmds):
    cmd, csize = struct.unpack_from('<II', data, off)
    if cmd == 0x2:  # LC_SYMTAB
        symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', data, off + 8)
        syms = (symoff, nsyms)
        strs = (stroff, strsize)
    off += csize

symoff, nsyms = syms
stroff, strsize = strs
print(f'nsyms={nsyms}')
for idx in (ORD,):
    e = symoff + idx * 16
    nstrx, ntype, nsect, ndesc, nvalue = struct.unpack_from('<IBBHQ', data, e)
    name = data[stroff+nstrx:stroff+nstrx+128].split(b'\x00')[0].decode(errors='replace')
    print(f'symbol[{idx}]: name={name!r} type={ntype:#x} sect={nsect} value={nvalue:#x}')
