"""cat_owner.py — find which category/class owns a given IMP (by scanning
catlist + classlist method lists for the IMP address)."""
import struct, bisect, sys

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
data = open(PATH, 'rb').read()
TARGET = int(sys.argv[1], 16)

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

def find_sections(name):
    return [(a, s, f) for a, s, f, sn in sects if sn == name]

def read_name(va):
    fo = vm_to_file(va)
    if fo is None: return b'?'
    e = data.find(b'\x00', fo, fo+256)
    if e < 0: return b'?'
    return data[fo:e]

def find_imp_in_list(list_va, want_imp):
    fo = vm_to_file(list_va)
    if fo is None: return None
    eaf, count = struct.unpack_from('<II', data, fo)
    if count == 0 or count > 0x40000: return None
    if eaf & 0x80000000:
        ent = list_va + 8
        for i in range(count):
            e_va = ent + i*12
            e_fo = vm_to_file(e_va)
            if e_fo is None: continue
            name_off, _t, imp_off = struct.unpack_from('<iii', data, e_fo)
            imp_va = e_va + 8 + imp_off
            if imp_va == want_imp:
                name_va = e_va + name_off
                return read_name(name_va)
    else:
        entsize = eaf & 0xFFFF
        if entsize < 16 or entsize > 64: return None
        ent = list_va + 8
        for i in range(count):
            e_va = ent + i*entsize
            e_fo = vm_to_file(e_va)
            if e_fo is None: continue
            imp_raw = struct.unpack_from('<Q', data, e_fo + 16)[0]
            imp_va = imp_raw & 0xFFFFFFFFF
            if imp_va == want_imp:
                name_raw = struct.unpack_from('<Q', data, e_fo)[0]
                return read_name(name_raw & 0xFFFFFFFFF)
    return None

# categories
for (va0, sz, fo) in find_sections('__objc_catlist'):
    n = sz // 8
    for i in range(n):
        raw = struct.unpack_from('<Q', data, fo + i*8)[0]
        if not raw: continue
        cat_va = raw & 0xFFFFFFFFF
        cfo = vm_to_file(cat_va)
        if cfo is None: continue
        cat_name = read_name(struct.unpack_from('<Q', data, cfo)[0] & 0xFFFFFFFFF)
        cls_raw = struct.unpack_from('<Q', data, cfo + 8)[0]
        cls_va = cls_raw & 0xFFFFFFFFF
        cls_name = b'?'
        if cls_va:
            c2fo = vm_to_file(cls_va)
            if c2fo:
                d_raw = struct.unpack_from('<Q', data, c2fo + 32)[0]
                if d_raw:
                    ro_va = d_raw & 0xFFFFFFFFF
                    rfo = vm_to_file(ro_va)
                    if rfo:
                        cls_name = read_name(struct.unpack_from('<Q', data, rfo + 24)[0] & 0xFFFFFFFFF)
        for moff in (16, 24):
            m_raw = struct.unpack_from('<Q', data, cfo + moff)[0]
            if not m_raw: continue
            sel = find_imp_in_list(m_raw & 0xFFFFFFFFF, TARGET)
            if sel is not None:
                print(f'CATEGORY: name={cat_name.decode(errors="replace")} cls={cls_name.decode(errors="replace")} cls_va={cls_va:#x} slot={moff} selector={sel.decode(errors="replace")}')
                sys.exit(0)
print('not in categories')
