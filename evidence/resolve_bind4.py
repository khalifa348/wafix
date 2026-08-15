"""resolve_bind4.py — resolve threaded-bind GOT slot via exports trie.
Usage: resolve_bind4.py <slot_va> <raw_slot_value_hex>
"""
import struct, sys

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
data = open(PATH, 'rb').read()
SLOT = int(sys.argv[1], 16)
RAW = int(sys.argv[2], 16)

# parse load commands
ncmds, = struct.unpack_from('<I', data, 16)
off = 32
exports = None
syms = None
strs = None
segments = []
for _ in range(ncmds):
    cmd, csize = struct.unpack_from('<II', data, off)
    if cmd == 0x1:  # LC_SEGMENT_64
        segname = data[off+8:off+24].rstrip(b'\x00').decode()
        vmaddr, vmsize, fileoff = struct.unpack_from('<QQQ', data, off + 0x18)
        segments.append((segname, vmaddr, vmsize, fileoff))
    if cmd == 0x2:  # LC_SYMTAB
        symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', data, off + 8)
        syms = (symoff, nsyms, stroff)
    if cmd == 0x80000023:  # LC_DYLD_EXPORTS_TRIE
        trie_off, trie_sz = struct.unpack_from('<II', data, off + 8)
        exports = (trie_off, trie_sz)
    off += csize

print('segments:')
for s in segments:
    print(f'  {s[0]:20s} va={s[1]:#x} size={s[2]:#x} fo={s[3]:#x}')

# threaded bind decode for DYLD_CHAINED_PTR_64 (bind bit 63)
BIND = RAW >> 63
ordinal = RAW & 0xFFFFFFFFF  # low 36 bits for 64_OFFSET... for plain 64: ordinal in low 36
print(f'bind={BIND} raw={RAW:#x} ordinal_candidate={ordinal:#x}')

# exports trie: walk terminal nodes, collect (name, flags, addr) in trie order
def parse_trie(buf, start, size):
    out = []
    def walk(node, suffix):
        i = node
        while True:
            term = buf[i]
            i += 1
            if term == 0:
                break
            if term & 0x80:
                # terminal
                usize, i = read_uleb(buf, i)
                uend = i + usize
                if usize > 0:
                    flags, i = read_uleb(buf, i)
                    addr = 0
                    if flags & 0x08:  # re-export
                        i = read_uleb(buf, i)
                    else:
                        addr, i = read_uleb(buf, i)
                        if flags & 0x10:  # stub
                            i = read_uleb(buf, i)
                        if flags & 0x40:  # resolver
                            i = read_uleb(buf, i)
                    out.append((suffix, flags, addr))
                i = uend
            nchild = buf[i]
            i += 1
            for _ in range(nchild):
                cedge = buf[i]
                i += 1
                edge = buf[i:i+cedge]
                i += cedge
                cnode, i = read_uleb(buf, i)
                walk(start + cnode, suffix + edge.decode(errors='replace'))
    walk(start, '')
    return out

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

trie_off, trie_sz = exports
trie = data[trie_off:trie_off+trie_sz]
syms_list = parse_trie(trie, 0, trie_sz)
print(f'exports trie: {len(syms_list)} symbols')
# ordinal in threaded bind = index into the bind-ordinal table = exports order?
if ordinal < len(syms_list):
    name, flags, addr = syms_list[ordinal]
    print(f'ordinal {ordinal}: {name} flags={flags:#x} addr={addr:#x}')
else:
    print(f'ordinal {ordinal} out of range')
    for k in range(min(5, len(syms_list))):
        print(f'  [{k}] {syms_list[k][0]} @ {syms_list[k][2]:#x}')
# search for resume-related exports
for nm, fl, ad in syms_list:
    if 'esume' in nm or 'ffline' in nm or 'Batching' in nm:
        print(f'  MATCH: {nm} flags={fl:#x} addr={ad:#x}')
