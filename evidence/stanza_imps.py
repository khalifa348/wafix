"""stanza_imps.py — enumerate IMPs of all methods whose selector matches
Stanza/Persist/NSE/Merge/XMPP/Stream patterns in NEW 26.24.72.
Walks __objc_classlist + __objc_catlist (absolute + relative method lists),
decodes chained pointers. Output: sorted list of name -> IMP vmaddrs.
"""
import struct, bisect, re

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

def find_sections(name):
    out = []
    for saddr, ssize, soff, sname in sects:
        if sname == name:
            out.append((saddr, ssize, soff))
    return out

PAT = re.compile(rb'(Stanza|Persist|NSE|Merge|XMPP|Stream|Xmpp|stanza|persist)')
results = []  # (selector_bytes, imp_va, owner_va, kind)

def walk_method_list(list_va, owner_va, kind):
    fo = vm_to_file(list_va)
    if fo is None:
        return
    eaf, count = struct.unpack_from('<II', data, fo)
    if count == 0 or count > 0x40000:
        return
    if eaf & 0x80000000:
        ent = list_va + 8
        for i in range(count):
            e_va = ent + i*12
            e_fo = vm_to_file(e_va)
            if e_fo is None:
                continue
            name_off, _t, imp_off = struct.unpack_from('<iii', data, e_fo)
            name_va = e_va + name_off
            imp_va = e_va + 8 + imp_off
            nfo = vm_to_file(name_va)
            if nfo is None:
                continue
            e = data.find(b'\x00', nfo, nfo+256)
            if e < 0:
                continue
            sb = data[nfo:e]
            if PAT.search(sb):
                results.append((sb, imp_va, owner_va, kind))
    else:
        entsize = eaf & 0xFFFF
        if entsize < 16 or entsize > 64:
            return
        ent = list_va + 8
        for i in range(count):
            e_va = ent + i*entsize
            e_fo = vm_to_file(e_va)
            if e_fo is None:
                continue
            name_raw = struct.unpack_from('<Q', data, e_fo)[0]
            name_va = name_raw & 0xFFFFFFFFF
            imp_raw = struct.unpack_from('<Q', data, e_fo + 16)[0]
            imp_va = imp_raw & 0xFFFFFFFFF
            nfo = vm_to_file(name_va)
            if nfo is None:
                continue
            e = data.find(b'\x00', nfo, nfo+256)
            if e < 0:
                continue
            sb = data[nfo:e]
            if PAT.search(sb):
                results.append((sb, imp_va, owner_va, kind))

# classes
for (va0, sz, fo) in find_sections('__objc_classlist'):
    n = sz // 8
    for i in range(n):
        raw = struct.unpack_from('<Q', data, fo + i*8)[0]
        if not raw:
            continue
        cls_va = raw & 0xFFFFFFFFF
        cfo = vm_to_file(cls_va)
        if cfo is None:
            continue
        d_raw = struct.unpack_from('<Q', data, cfo + 32)[0]
        if not d_raw:
            continue
        ro_va = d_raw & 0xFFFFFFFFF
        rfo = vm_to_file(ro_va)
        if rfo is None:
            continue
        m_raw = struct.unpack_from('<Q', data, rfo + 32)[0]
        if m_raw:
            walk_method_list(m_raw & 0xFFFFFFFFF, cls_va, 'cls')

# categories
for (va0, sz, fo) in find_sections('__objc_catlist'):
    n = sz // 8
    for i in range(n):
        raw = struct.unpack_from('<Q', data, fo + i*8)[0]
        if not raw:
            continue
        cat_va = raw & 0xFFFFFFFFF
        cfo = vm_to_file(cat_va)
        if cfo is None:
            continue
        for moff in (16, 24):
            m_raw = struct.unpack_from('<Q', data, cfo + moff)[0]
            if m_raw:
                walk_method_list(m_raw & 0xFFFFFFFFF, cat_va, 'cat')

# dedupe by (selector, imp)
seen = set()
uniq = []
for sb, imp_va, owner, kind in results:
    key = (sb, imp_va)
    if key in seen:
        continue
    seen.add(key)
    uniq.append((sb, imp_va, owner, kind))

uniq.sort(key=lambda t: t[1])
print(f'total unique stanza-ish methods: {len(uniq)}')
for sb, imp_va, owner, kind in uniq:
    print(f'{imp_va:#x} [{kind}] {sb.decode()}')
