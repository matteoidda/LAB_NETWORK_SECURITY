import struct, collections, re, sys

PCAP = 'capture.pcap'
FORM = 'expense-form.txt'

def load_pcap(path):
    d = open(path, 'rb').read()
    off = 24
    pkts = []
    while off + 16 <= len(d):
        incl = struct.unpack('<I', d[off+8:off+12])[0]
        off += 16
        pkts.append(d[off:off+incl])
        off += incl
    return pkts

def dot11(raw):
    rtlen = struct.unpack('<H', raw[2:4])[0]
    body = raw[rtlen:]
    fc = struct.unpack('<H', body[0:2])[0]
    return body, fc

def macfields(fc):
    ftype = (fc >> 2) & 3
    fsub = (fc >> 4) & 0xf
    tods = (fc >> 8) & 1
    fromds = (fc >> 9) & 1
    retry = (fc >> 11) & 1
    prot = (fc >> 14) & 1
    return ftype, fsub, tods, fromds, retry, prot

def hdrlen(fsub, tods, fromds):
    h = 24
    if tods and fromds: h += 6
    if fsub >= 8: h += 2
    return h

pkts = load_pcap(PCAP)

victim = None
replays = collections.Counter()
seen = collections.Counter()
for raw in pkts:
    body, fc = dot11(raw)
    if len(body) < 2: continue
    ftype, fsub, tods, fromds, retry, prot = macfields(fc)
    if ftype != 2 or prot: continue
    h = hdrlen(fsub, tods, fromds)
    rest = body[h:]
    if len(rest) >= 8 and rest[:6] == b'\xaa\xaa\x03\x00\x00\x00':
        if struct.unpack('>H', rest[6:8])[0] == 0x888e:
            eapol = rest[8:]
            if len(eapol) >= 7:
                keyinfo = struct.unpack('>H', eapol[5:7])[0]
                dst = body[4:10]
                src = body[10:16]
                is_msg3 = (keyinfo & 0x0008) and (keyinfo & 0x0080) and (keyinfo & 0x0100)
                if is_msg3:
                    seen[dst] += 1
                    if seen[dst] > 1:
                        victim = dst

frames = collections.defaultdict(list)
for idx, raw in enumerate(pkts):
    body, fc = dot11(raw)
    if len(body) < 2: continue
    ftype, fsub, tods, fromds, retry, prot = macfields(fc)
    if ftype != 2 or not prot: continue
    if body[10:16] != victim: continue
    h = hdrlen(fsub, tods, fromds)
    rest = body[h:]
    if len(rest) < 8: continue
    c = rest[:8]
    pn = (c[7]<<40)|(c[6]<<32)|(c[5]<<24)|(c[4]<<16)|(c[1]<<8)|c[0]
    frames[pn].append((idx, rest[8:]))

known = open(FORM, 'rb').read()
HDR = 48
target_len = HDR + len(known) + 8

known_frame = None
for pn in frames:
    for idx, enc in frames[pn]:
        if len(enc) == target_len:
            known_frame = (pn, idx, enc)
            break
    if known_frame: break

pn, kidx, C_known = known_frame
partner = None
for idx, enc in frames[pn]:
    if idx != kidx and enc != C_known:
        partner = (idx, enc)
        break

pidx, C_secret = partner
ks = bytes(a ^ b for a, b in zip(C_known[HDR:HDR+len(known)], known))
plain = bytes(a ^ b for a, b in zip(C_secret[HDR:], ks))

print("victim:", victim.hex())
print("reused PN:", pn, "known-frame idx:", kidx, "secret-frame idx:", pidx)
print("-"*60)
print(plain.decode('latin-1'))
print("-"*60)
m = re.search(rb'netsec\{[^}]*\}', plain)
print("FLAG:", m.group().decode() if m else "not found")
