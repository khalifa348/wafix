"""Reach analysis v3: find callers of processPersistedStanza:...nseMergeCompletion:
iOS 26 uses dyld chained fixups -> selref slots on disk are NOT raw pointers.
Instead: find ADRP+ADD/LDR code that targets ANY address inside __objc_selrefs,
then decode the chained-fixup target of each referenced slot to identify which
selector each call site uses.
"""
import struct, sys

PATH = r'C:\Users\User\Desktop\mac_vm\ipa_works\wa_new_2624\Payload\WhatsApp.app\WhatsApp'
SEL_STR = b'processPersistedStanza:inPersistentStanzaQueue:isFromDeferredNSEMerge:nseMergeCompletion:'

data = open(PATH, 'rb').read()
print(f'file size {len(data)}', flush=True)

# ---- parse Mach-O 64 load commands ----
magic = struct.unpack_from('<I', data, 0)[0]
assert magic == 0xFEEDFACF, hex(magic)
ncmds = struct.unpack_from('<I', data, 0x10)[0]
segs = []      # (segname, vmaddr, fileoff, filesize)
sects = []     # (sectname, segname, addr, size, fileoff)
off = 0x20
for _ in range(ncmds):
    cmd, sz = struct.unpack_from('<II', data, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[off+8:off+24].split(b'\0')[0].decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off+0x18)
        nsects = struct.unpack_from('<I', data, off+0x40)[0]
        segs.append((segname, vmaddr, fileoff, filesize))
        for si in range(nsects):
            so = off + 0x48 + si*0x50
            sname = data[so:so+16].split(b'\0')[0].decode()
            sseg = data[so+16:so+32].split(b'\0')[0].decode()
            saddr, ssize = struct.unpack_from('<QQ', data, so+0x20)
            soff = struct.unpack_from('<I', data, so+0x30)[0]
            sects.append((sname, sseg, saddr, ssize, soff))
            if sname in ('__objc_selrefs','__objc_methname','__objc_msgrefs'):
                print(f'  sect {sseg}/{sname:16s} vm={saddr:#x} size={ssize:#x} fileoff={soff:#x}', flush=True)
    off += sz

def file_to_vm(foff):
    for segname, vmaddr, fileoff, filesize in segs:
        if fileoff <= foff < fileoff + filesize:
            return vmaddr + (foff - fileoff)
    return None

def adrp_target(pc_vm, word):
    immhi = (word >> 5) & 0x7FFFF
    immlo = (word >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    return ((pc_vm >> 12) + imm) << 12

# ---- SELF-TEST: ADRP decoder vs capstone ----
try:
    import capstone, random
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    text_seg = [s for s in segs if s[0] == '__TEXT'][0]
    t_off, t_size = text_seg[2], text_seg[3]
    random.seed(42)
    tested = checked = 0
    for _ in range(3000):
        ro = t_off + random.randrange(0, max(1, t_size - 8))
        word = struct.unpack_from('<I', data, ro)[0]
        if (word & 0x9F000000) != 0x90000000:
            continue
        pc_vm = file_to_vm(ro)
        mine = adrp_target(pc_vm, word)
        insns = list(md.disasm(data[ro:ro+4], pc_vm))
        if not insns:
            continue
        cs_imm = next((op.imm for op in insns[0].operands
                       if op.type == capstone.arm64.ARM64_OP_IMM), None)
        tested += 1
        if cs_imm is not None:
            checked += 1
            assert mine == (cs_imm & ~0xFFF), f'adrp mismatch @{pc_vm:#x}: mine={mine:#x} cs={cs_imm:#x}'
    print(f'SELF-TEST OK: {checked}/{tested} ADRP samples match capstone', flush=True)
except ImportError:
    print('SELF-TEST SKIPPED: capstone not available', flush=True)

# ---- selector vm ----
idx = data.find(SEL_STR)
SEL_VM = file_to_vm(idx)
print(f'selector "{SEL_STR[:40]}..." at vm {SEL_VM:#x}', flush=True)
assert SEL_VM

# ---- selref section range ----
selrefs_sect = [s for s in sects if s[0] == '__objc_selrefs']
if not selrefs_sect:
    print('NO __objc_selrefs section', flush=True)
    sys.exit(0)
sname, sseg, saddr, ssize, soff = selrefs_sect[0]
selref_lo, selref_hi = saddr, saddr + ssize
print(f'selref range: {selref_lo:#x}..{selref_hi:#x}', flush=True)

# ---- scan __TEXT for ADRP+{ADD,LDR} referencing selref range ----
text_seg = [s for s in segs if s[0] == '__TEXT'][0]
t_lo, t_hi = text_seg[2], text_seg[2] + text_seg[3]
hits = []  # (fileoff, vm, kind, reg, selref_vm)
for off in range(t_lo, t_hi - 8, 4):
    word = struct.unpack_from('<I', data, off)[0]
    if (word & 0x9F000000) != 0x90000000:
        continue
    pc_vm = file_to_vm(off)
    tgt_page = adrp_target(pc_vm, word)
    rd = word & 0x1F
    for j in range(1, 8):
        w2 = struct.unpack_from('<I', data, off + 4*j)[0]
        kind = None
        if (w2 & 0xFFC00000) == 0x91000000:   # ADD imm
            kind = 'ADD'
            rn = (w2 >> 5) & 0x1F
            imm = (w2 >> 10) & 0xFFF
            addr = tgt_page + imm
        elif (w2 & 0xFFC00000) == 0xF9400000:  # LDR imm unsigned
            kind = 'LDR'
            rn = (w2 >> 5) & 0x1F
            imm = ((w2 >> 10) & 0xFFF) << 3
            addr = tgt_page + imm
        else:
            continue
        if rn == rd and selref_lo <= addr < selref_hi:
            hits.append((off, file_to_vm(off), kind, rd, addr))
            break
print(f'code refs into selref range: {len(hits)}', flush=True)

seen = {}
for off, vm, kind, reg, slot_vm in hits:
    seen.setdefault(slot_vm, []).append((vm, kind))
print(f'unique referenced slots: {len(seen)}', flush=True)

# ---- identify slots pointing to OUR selector via chained-fixup encoding ----
# DYLD_CHAINED_PTR_64_OFFSET: low 36 bits = vm offset of target from image base.
def slot_target(slot_vm):
    slot_file = None
    for sname2, sseg2, saddr2, ssize2, soff2 in sects:
        if saddr2 <= slot_vm < saddr2 + ssize2 and sseg2 in ('__DATA', '__DATA_CONST'):
            slot_file = soff2 + (slot_vm - saddr2)
            break
    if slot_file is None:
        return None
    val = struct.unpack_from('<Q', data, slot_file)[0]
    return (val & 0xFFFFFFFFF)  # low 36 bits = target vm offset from image base

sel_target = SEL_VM  # encoding stores full vm addr in low 36 bits (high 16 = next field)
my_slots = [sv for sv in seen if slot_target(sv) == sel_target]
print(f'slots pointing to our selector: {len(my_slots)}', flush=True)
for sv in my_slots:
    refs = seen[sv]
    print(f'  slot {sv:#x} refs={len(refs)} first={refs[0]}', flush=True)

# ---- disassemble around code refs of our slots ----
if my_slots:
    import capstone as cs_lib
    md = cs_lib.Cs(cs_lib.CS_ARCH_ARM64, cs_lib.CS_MODE_ARM)
    shown = 0
    for sv in my_slots:
        for ref_vm, kind in seen[sv][:3]:
            # find file offset of ref_vm
            ref_off = None
            for sname2, sseg2, saddr2, ssize2, soff2 in sects:
                if saddr2 <= ref_vm < saddr2 + ssize2 and sseg2 == '__TEXT':
                    ref_off = soff2 + (ref_vm - saddr2)
                    break
            if ref_off is None:
                continue
            start = ref_off - 0x20
            code = data[start:start + 0xC0]
            print(f'\n--- caller disasm near {ref_vm:#x} ---', flush=True)
            for insn in md.disasm(code, file_to_vm(start)):
                print(f'  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}', flush=True)
                if insn.address > ref_vm + 0x60:
                    break
            shown += 1
            if shown >= 2:
                break
        if shown >= 2:
            break
