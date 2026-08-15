"""Differential: find IMP of processPersistedStanza:...nseMergeCompletion: in OLD
via __objc_classlist -> class_ro_t -> baseMethods -> method_list, then check
whether OLD has a bounds guard before the table read (NEW lacks it)."""
import struct

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa-business-decrypted\Payload\WhatsApp.app\WhatsApp'
SEL = b'processPersistedStanza:inPersistentStanzaQueue:isFromDeferredNSEMerge:nseMergeCompletion:'
BASE = 0x100000000

data = open(PATH, 'rb').read()
print(f'file {len(data)} bytes')

# ---- collect sections ----
sects = []  # (segname, sectname, vmaddr, size, fileoff)
magic = struct.unpack_from('<I', data, 0)[0]
assert magic == 0xfeedfacf
ncmds, = struct.unpack_from('<I', data, 16)
off = 32
for _ in range(ncmds):
    cmd, csize = struct.unpack_from('<II', data, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[off+8:off+24].rstrip(b'\x00').decode()
        nsects, = struct.unpack_from('<I', data, off+64)
        so = off + 72
        for _ in range(nsects):
            sname = data[so:so+16].rstrip(b'\x00').decode()
            saddr, ssize = struct.unpack_from('<QQ', data, so+0x20)
            soff = struct.unpack_from('<I', data, so+0x30)[0]
            sects.append((segname, sname, saddr, ssize, soff))
            so += 80
    off += csize

def file_to_vm(fo):
    for seg, sn, va, sz, fo2 in sects:
        if fo2 <= fo < fo2 + sz and seg == '__TEXT':
            return va + (fo - fo2)
    return None

def vm_to_file(va):
    for seg, sn, va2, sz, fo2 in sects:
        if va2 <= va < va2 + sz:
            return fo2 + (va - va2)
    return None

# ---- selector vm ----
pos = data.find(SEL)
print(f'selector fileoff={pos:#x} vm={file_to_vm(pos):#x}')
SEL_VM = file_to_vm(pos)

# ---- __objc_classlist / __objc_data ----
cls = [s for s in sects if s[1] == '__objc_classlist'][0]
clsoff = vm_to_file(cls[2])
ncls = cls[3] // 8
print(f'__objc_classlist: {ncls} classes')

def read_ptr(fo):
    return struct.unpack_from('<Q', data, fo)[0]

def deref(va):
    fo = vm_to_file(va)
    return fo

# walk classes; class_t: isa(8) superclass(8) cache(8) vtable(8) data(8) = 40 bytes
# data -> class_ro_t: flags(4) instanceStart(4) instanceSize(4) reserved(4)
#   ivarLayout(8) name(8) baseMethods(8) baseProtocols(8) ivars(8) weakIvarLayout(8) baseProperties(8)
found = []
for i in range(ncls):
    cfo = clsoff + i*8
    cls_va = read_ptr(cfo)
    if not cls_va:
        continue
    cfo2 = deref(cls_va)
    if cfo2 is None:
        continue
    data_va = read_ptr(cfo2 + 32)
    if not data_va:
        continue
    dfo = deref(data_va)
    if dfo is None:
        continue
    methods_va = read_ptr(dfo + 24)  # baseMethods
    if not methods_va:
        continue
    mfo = deref(methods_va)
    if mfo is None:
        continue
    entsize, count = struct.unpack_from('<II', data, mfo + 4)
    if entsize & 0x80000000:  # relative method lists (arm64e)
        # relative: name(4) types(4) imp(4) - offsets from each field
        for mi in range(count):
            mfo_i = mfo + 8 + mi * 12
            name_off = struct.unpack_from('<i', data, mfo_i)[0]
            imp_off = struct.unpack_from('<i', data, mfo_i + 8)[0]
            name_va = (mfo_i + 0) + name_off
            imp_va = (mfo_i + 8) + imp_off
            nfo = vm_to_file(name_va)
            if nfo is not None:
                s = data[nfo:nfo+len(SEL)]
                if s == SEL:
                    found.append((cls_va, imp_va))
    else:
        for mi in range(count):
            mfo_i = mfo + 16 + mi * entsize
            name_va = read_ptr(mfo_i)
            imp_va = read_ptr(mfo_i + 16)
            nfo = vm_to_file(name_va)
            if nfo is not None:
                s = data[nfo:nfo+len(SEL)]
                if s == SEL:
                    found.append((cls_va, imp_va))

print(f'IMP(s) found: {len(found)}')
for cls_va, imp_va in found[:5]:
    print(f'  class={cls_va:#x} IMP={imp_va:#x}')
    # disasm IMP prologue + the table-read site with capstone
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        ifo = vm_to_file(imp_va)
        code = data[ifo:ifo+0x400]
        for insn in md.disasm(code, imp_va):
            print(f'    {insn.address:#x}: {insn.mnemonic:9s} {insn.op_str}')
            if insn.address > imp_va + 0x140:
                break
    except ImportError:
        pass
