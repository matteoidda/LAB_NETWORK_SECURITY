import os
import struct
import sys
import hashlib
from collections import defaultdict, Counter

PCAP = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), 'capture-12.pcap')
C2 = 'syncbridge.example'
GREASE = {0x0a0a + 0x1010 * i for i in range(16)}
TLS_VERSIONS = {0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3'}


def read_packets(path):
    data = open(path, 'rb').read()
    magic = struct.unpack('<I', data[:4])[0]
    endian = '<' if magic in (0xa1b2c3d4, 0xa1b23c4d) else '>'
    div = 1e9 if magic in (0xa1b23c4d, 0x4d3cb2a1) else 1e6
    off = 24
    while off + 16 <= len(data):
        sec, frac, caplen, _ = struct.unpack(endian + 'IIII', data[off:off + 16])
        off += 16
        ip = data[off + 14:off + caplen]
        off += caplen
        if ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        tcp = ip[(ip[0] & 15) * 4:]
        sport, dport, seq = struct.unpack('>HHI', tcp[:8])
        doff = (tcp[12] >> 4) * 4
        yield (sec + frac / div, '.'.join(map(str, ip[12:16])), sport, dport, seq, tcp[doff:])


def client_hellos(path):
    streams = defaultdict(dict)
    start = {}
    for t, src, sport, dport, seq, payload in read_packets(path):
        if dport != 443 or not payload:
            continue
        key = (src, sport)
        start.setdefault(key, t)
        streams[key][seq] = payload
    for key, segments in streams.items():
        stream = b''.join(segments[s] for s in sorted(segments))
        handshake = b''
        i = 0
        while i + 5 <= len(stream) and stream[i] == 0x16:
            length = struct.unpack('>H', stream[i + 3:i + 5])[0]
            handshake += stream[i + 5:i + 5 + length]
            i += 5 + length
        if handshake[:1] == b'\x01':
            length = int.from_bytes(handshake[1:4], 'big')
            yield start[key], key[0], key[1], handshake[4:4 + length]


def u16_list(buf):
    return [struct.unpack('>H', buf[j:j + 2])[0] for j in range(0, len(buf), 2)]


def parse_client_hello(ch):
    legacy_version = struct.unpack('>H', ch[:2])[0]
    i = 34
    i += 1 + ch[i]
    n = struct.unpack('>H', ch[i:i + 2])[0]
    ciphers = u16_list(ch[i + 2:i + 2 + n])
    i += 2 + n
    i += 1 + ch[i]
    end = i + 2 + struct.unpack('>H', ch[i:i + 2])[0]
    i += 2
    extensions, sni, alpn, sigalgs, versions = [], None, [], [], []
    while i < end:
        ext_type, length = struct.unpack('>HH', ch[i:i + 4])
        body = ch[i + 4:i + 4 + length]
        extensions.append(ext_type)
        if ext_type == 0x0000:
            name_len = struct.unpack('>H', body[3:5])[0]
            sni = body[5:5 + name_len].decode()
        elif ext_type == 0x0010:
            j = 2
            while j < len(body):
                alpn.append(body[j + 1:j + 1 + body[j]].decode(errors='replace'))
                j += 1 + body[j]
        elif ext_type == 0x000d:
            n = struct.unpack('>H', body[:2])[0]
            sigalgs = u16_list(body[2:2 + n])
        elif ext_type == 0x002b:
            versions = u16_list(body[1:1 + body[0]])
        i += 4 + length
    return legacy_version, ciphers, extensions, sni, alpn, sigalgs, versions


def sha12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12] if text else '000000000000'


def ja4(ch):
    legacy_version, ciphers, extensions, sni, alpn, sigalgs, versions = parse_client_hello(ch)
    ciphers = [c for c in ciphers if c not in GREASE]
    extensions = [e for e in extensions if e not in GREASE]
    sigalgs = [s for s in sigalgs if s not in GREASE]
    versions = [v for v in versions if v not in GREASE] or [legacy_version]

    version = TLS_VERSIONS.get(max(versions), '00')
    sni_flag = 'd' if sni else 'i'
    first_alpn = alpn[0] if alpn else ''
    alpn_chars = first_alpn[0] + first_alpn[-1] if first_alpn else '00'
    part_a = f't{version}{sni_flag}{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}{alpn_chars}'

    cipher_str = ','.join(f'{c:04x}' for c in sorted(ciphers))
    ext_str = ','.join(f'{e:04x}' for e in sorted(e for e in extensions if e not in (0x0000, 0x0010)))
    if sigalgs:
        ext_str += '_' + ','.join(f'{s:04x}' for s in sigalgs)

    return sni, f'{part_a}_{sha12(cipher_str)}_{sha12(ext_str)}', f'{part_a}_{cipher_str}_{ext_str}'


connections = []
for t, src, sport, ch in client_hellos(PCAP):
    sni, fingerprint, raw = ja4(ch)
    connections.append(dict(t=t, src=src, sport=sport, sni=sni, ja4=fingerprint, ja4_r=raw))
connections.sort(key=lambda c: c['t'])
print(f'ClientHello: {len(connections)}')

print('\nJA4 presenti:')
for fingerprint, count in Counter(c['ja4'] for c in connections).most_common():
    print(f'  {count:4}  {fingerprint}')

anchor = next(c for c in connections if c['sni'] and c['sni'].endswith(C2))
print(f"\nAnchor: {anchor['src']}:{anchor['sport']}  SNI={anchor['sni']}  JA4={anchor['ja4']}")

anchor_parts = anchor['ja4'].split('_')
for idx, name in enumerate('abc'):
    shared = sum(c['ja4'].split('_')[idx] == anchor_parts[idx] for c in connections)
    print(f'  parte {name} = {anchor_parts[idx]}  condivisa da {shared} connessioni')

malware = [c for c in connections if c['ja4'] == anchor['ja4']]
print(f'\nConnessioni del malware: {len(malware)}')
for c in malware:
    print(f"  {c['src']:12} {c['sport']:6}  {c['sni']}")

token = ''.join(c['sni'].split('.')[0] for c in malware)
print(f'\nFLAG: netsec{{{token}}}')



