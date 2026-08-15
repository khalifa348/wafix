"""t7_scan_newest.py — check if the 26.30.77 binary still has the t7 offline-resume pattern.
Search for: (a) the selector string, (b) the exact unchecked ldrsw->ldr byte pattern
that exists at 0x100337b88 in 26.24.72.
"""
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\User\Desktop\mac_vm\ipa_works\WhatsApp-Genuine\Payload\WhatsApp.app\WhatsApp'

with open(PATH, 'rb') as f:
    data = f.read()
print(f'file: {PATH} size={len(data)}')

# (a) selector string
sel = b'didOfflineResumeStartWithType:totalStanzasCount:'
idx = data.find(sel)
print(f'selector string @ fileoff {idx:#x}' if idx >= 0 else 'selector string NOT FOUND')

# (b) the exact pattern bytes from 26.24.72 @0x100337b88 (capstone-verified):
#   ldrsw x8,[x8,#0x10]  = 08 11 80 b9 (LDURSW, 0xB9801108)
#   ldr   x25,[x21,x8]   = b9 6a 68 f8 (LDR x25,[x21,x8], 0xF8686AB9)
pat = bytes.fromhex('081180b9') + bytes.fromhex('b96a68f8')
hits = []
i = 0
while True:
    i = data.find(pat, i)
    if i < 0:
        break
    hits.append(i)
    i += 1
print(f'ldrsw->ldr pattern hits: {len(hits)}')
for h in hits[:10]:
    print(f'  fileoff {h:#x} -> va {0x100000000 + h:#x}')

# also the LDURSW-with-x21-index variant ldr x25,[x21,x8] alone
pat2 = bytes.fromhex('787a68f8')
c2 = 0
i = 0
while True:
    i = data.find(pat2, i)
    if i < 0:
        break
    c2 += 1
    i += 1
print(f'ldr x25,[x21,x8] alone: {c2} hits')
