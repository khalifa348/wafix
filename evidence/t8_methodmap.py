#!/usr/bin/env python
"""Map candidate OOB sites to containing ObjC method names.
arm64e-aware: walks __objc_methlist (relative + absolute lists),
decodes chained-fixup selref slots for selector names."""
import glob, struct, re, bisect

IMG_BASE = 0x100000000
p = glob.glob(r'C:\Users\User\zdl_stage\t8_work\Payload\**\WhatsApp', recursive=True)[0]
data = open(p, 'rb').read()

# ---------- parse sections ----------
sections = {}  # (seg, sn) -> (addr, size, fileoff)
off = 32
ncmds = struct.unpack('<I', data[16:20])[0]
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack('<II', data[off:off+8])
    if cmd == 0x19:
        seg = data[off+8:off+24].split(b'\0')[0].decode()
        nsects = struct.unpack('<I', data[off+64:off+68])[0]
        for s in range(nsects):
            so = off + 72 + s*80
            sn = data[so:so+16].split(b'\0')[0].decode()
            addr = struct.unpack('<Q', data[so+32:so+40])[0]
            size = struct.unpack('<Q', data[so+40:so+48])[0]
            fo = struct.unpack('<I', data[so+48:so+52])[0]
            sections[(seg, sn)] = (addr, size, fo)
    off += cmdsize

def fo_at(addr):
    for (seg, sn), (a, sz, fo) in sections.items():
        if a <= addr < a + sz:
            return fo + (addr - a)
    return None

# ---------- selector string map ----------
saddr, ssize, sfo = sections[('__TEXT', '__objc_methname')]
selmap = {}
for m in re.finditer(rb'[\x20-\x7e]{2,}', data[sfo:sfo+ssize]):
    selmap[saddr + m.start()] = m.group(0).decode(errors='replace')

def string_at(addr, maxlen=256):
    f = fo_at(addr)
    if f is None: return None
    b = data[f:f+maxlen].split(b'\0')[0]
    if b and all(32 <= c < 127 for c in b):
        return b.decode(errors='replace')
    return None

def decode_selref_slot(slot_addr):
    """slot in __objc_selrefs holds chained (or raw) ptr to selector string.
    arm64e chained: target = low 32 bits as vm offset from image base."""
    f = fo_at(slot_addr)
    if f is None: return None
    val = struct.unpack('<Q', data[f:f+8])[0]
    if val == 0: return None
    if val & 0x8000000000000000:
        # authenticated chained pointer: target in low 32 bits
        return string_at(IMG_BASE + (val & 0xFFFFFFFF))
    if val >> 32:
        # unauthenticated chained (or raw): try image-relative decode first
        s = string_at(IMG_BASE + (val & 0xFFFFFFFF))
        if s: return s
    # maybe raw pointer into methname
    return string_at(val)

# ---------- walk method lists ----------
ma, msize, mfo = sections[('__TEXT', '__objc_methlist')]
methods = []  # (imp, name)
REL = 0x80000000
pos = 0
n_lists = 0
while pos + 8 <= msize:
    entsize_flags = struct.unpack('<I', data[mfo+pos: mfo+pos+4])[0]
    count = struct.unpack('<I', data[mfo+pos+4: mfo+pos+8])[0]
    entsize = entsize_flags & 0x7FFFFFFC  # 32-bit mask (removes flag bit 31 + low 2 bits)
    is_rel = bool(entsize_flags & REL)
    list_addr = ma + pos
    if not ((is_rel and entsize == 12) or (not is_rel and entsize == 24)) or count > 50000:
        pos += 4
        continue
    n_lists += 1
    for i in range(count):
        e = mfo + pos + 8 + i*entsize
        if is_rel:
            name_off = struct.unpack('<i', data[e:e+4])[0]
            imp_off = struct.unpack('<i', data[e+8:e+12])[0]
            name_ref = list_addr + 8 + i*12 + name_off
            imp = list_addr + 8 + i*12 + 8 + imp_off
        else:
            name_ref = struct.unpack('<Q', data[e:e+8])[0]
            imp = struct.unpack('<Q', data[e+16:e+24])[0]
        # name: if ref lands inside selrefs section -> decode slot; else direct string
        s = decode_selref_slot(name_ref)
        if s is None:
            s = string_at(name_ref)
        if s is None:
            s = '?'
        if 0x100000000 < imp < 0x110000000:
            methods.append((imp, s))
    pos += 8 + count*entsize

print('method lists:', n_lists, '| methods:', len(methods))
methods.sort()
with open(r'C:\Users\User\zdl_stage\t8_methods.txt', 'w') as f:
    for imp, name in methods:
        f.write('%X %s\n' % (imp, name))

def method_at(addr):
    idx = bisect.bisect_right(methods, (addr, '')) - 1
    if idx >= 0:
        imp, name = methods[idx]
        if imp <= addr and addr - imp < 0x4000:  # within 16KB of method start
            return name
    return '?'

# ---------- annotate candidates ----------
lines = open(r'C:\Users\User\zdl_stage\t8_scan_candidates.txt', encoding='utf-8').read().splitlines()
out = []
for l in lines:
    m = re.match(r'^(0x[0-9A-F]+)\s', l)
    if m:
        site = int(m.group(1), 16)
        out.append('%s   [method: %s]' % (l, method_at(site)))
    else:
        out.append(l)
open(r'C:\Users\User\zdl_stage\t8_scan_candidates.txt', 'w', encoding='utf-8').write('\n'.join(out))
print('annotated.')
