"""resolve_imps.py — selector -> IMP resolver for iOS 26 (arm64e, chained fixups).
Single pass over __objc_classlist + __objc_catlist; bisect-based file mapping.
"""
import struct, sys, bisect

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
data = open(PATH, 'rb').read()

# ---- sections (sorted by vmaddr for bisect) ----
sects = []  # (vmaddr, size, fileoff)
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
            sects.append((saddr, ssize, soff))
            so += 80
    off += csize
sects.sort()
vmaddrs = [s[0] for s in sects]

def vm_to_file(va):
    i = bisect.bisect_right(vmaddrs, va) - 1
    if i < 0:
        return None
    va0, sz, fo = sects[i]
    if va < va0 + sz:
        return fo + (va - va0)
    return None

def read_q(va):
    fo = vm_to_file(va)
    if fo is None:
        return None
    v = struct.unpack_from('<Q', data, fo)[0]
    return v & 0xFFFFFFFFF if v else 0

def read_i32(va):
    fo = vm_to_file(va)
    if fo is None:
        return None
    return struct.unpack_from('<i', data, fo)[0]

FAST_DATA_MASK = 0x00007ffffffffff8

# ---- selectors to resolve ----
SEL_BYTES = [
    b'processPersistedStanza:inPersistentStanzaQueue:isFromDeferredNSEMerge:nseMergeCompletion:',
    b'processPersistedIncomingMessageStanza:',
    b'processPersistedIncomingOrderedNotificationStanza:',
    b'processPersistedIncomingReceiptStanza:',
    b'processIncomingMessageStanza:',
    b'processIncomingReceiptStanza:',
    b'processIncomingNotificationStanza:',
    b'processIncomingAckStanza:',
    b'processIncomingCallStanza:',
    b'processIncomingChatStateStanza:',
    b'processIncomingCustomStanza:',
    b'processIncomingIQStanza:isResponse:',
    b'processIncomingPresenceStanza:',
]
SEL_SET = set(SEL_BYTES)
found = {s: [] for s in SEL_BYTES}

def walk_method_list(list_va):
    fo = vm_to_file(list_va)
    if fo is None:
        return
    eaf, count = struct.unpack_from('<II', data, fo)  # entsizeAndFlags @ +0, count @ +4
    if count == 0 or count > 0x40000:
        return
    if eaf & 0x80000000:
        # relative list: header 8 bytes, entries 12 bytes (name_off, types_off, imp_off)
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
            if sb in SEL_SET:
                found[sb].append((name_va, imp_va))
    else:
        entsize = eaf & 0xFFFF
        if entsize < 16 or entsize > 64:
            return
        ent = list_va + 8
        for i in range(count):
            e_va = ent + i*entsize
            name_va = read_q(e_va)
            imp_va = read_q(e_va + 16)
            nfo = vm_to_file(name_va) if name_va else None
            if nfo is None:
                continue
            e = data.find(b'\x00', nfo, nfo+256)
            if e < 0:
                continue
            sb = data[nfo:e]
            if sb in SEL_SET:
                found[sb].append((name_va, imp_va))

# ---- single pass over classes ----
def scan_classlist(secname):
    for (va0, sz, fo) in sects:
        pass
    # find section by scanning header names separately
    return []

def scan_all():
    ncls_total = 0
    # find classlist/catlist sections
    ncmds2, = struct.unpack_from('<I', data, 16)
    off2 = 32
    cls_lists = []
    cat_lists = []
    for _ in range(ncmds2):
        cmd, csize = struct.unpack_from('<II', data, off2)
        if cmd == 0x19:
            nsects, = struct.unpack_from('<I', data, off2+64)
            so = off2 + 72
            for _ in range(nsects):
                sname = data[so:so+16].rstrip(b'\x00').decode()
                saddr, ssize = struct.unpack_from('<QQ', data, so+0x20)
                soff = struct.unpack_from('<I', data, so+0x30)[0]
                if sname == '__objc_classlist':
                    cls_lists.append((saddr, ssize, soff))
                elif sname == '__objc_catlist':
                    cat_lists.append((saddr, ssize, soff))
                so += 80
        off2 += csize

    for (va0, sz, fo) in cls_lists:
        n = sz // 8
        ncls_total += n
        for i in range(n):
            cls_va = struct.unpack_from('<Q', data, fo + i*8)[0]
            if not cls_va:
                continue
            cls_va &= 0xFFFFFFFFF
            cfo = vm_to_file(cls_va)
            if cfo is None:
                continue
            data_raw = struct.unpack_from('<Q', data, cfo + 32)[0]
            if not data_raw:
                continue
            ro_va = data_raw & 0xFFFFFFFFF  # chain-decode too
            rfo = vm_to_file(ro_va)
            if rfo is None:
                continue
            methods_raw = struct.unpack_from('<Q', data, rfo + 32)[0]  # baseMethods @ +32
            if not methods_raw:
                continue
            walk_method_list(methods_raw & 0xFFFFFFFFF)
    print(f'classes scanned: {ncls_total}')

    for (va0, sz, fo) in cat_lists:
        n = sz // 8
        for i in range(n):
            cat_va = struct.unpack_from('<Q', data, fo + i*8)[0]
            if not cat_va:
                continue
            cat_va &= 0xFFFFFFFFF
            cfo = vm_to_file(cat_va)
            if cfo is None:
                continue
            for moff in (16, 24):  # instanceMethods, classMethods
                m_va = struct.unpack_from('<Q', data, cfo + moff)[0]
                if m_va:
                    walk_method_list(m_va & 0xFFFFFFFFF)

scan_all()
for sb in SEL_BYTES:
    r = found[sb]
    print(f'{sb.decode()[:70]:70s} -> {len(r)} IMP(s)')
    for name_va, imp_va in r[:3]:
        print(f'    IMP={imp_va:#x}')
