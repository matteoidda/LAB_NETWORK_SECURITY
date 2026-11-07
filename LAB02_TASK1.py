import struct
import sys
import re
from collections import defaultdict, Counter


PCAP = sys.argv[1] if len(sys.argv) > 1 else 'capture-1.pcap'
NAT = '198.51.100.7'



def packets(path):
    d = open(path, 'rb').read()
    magic = struct.unpack('<I', d[:4])[0]
    e = '<' if magic in (0xa1b2c3d4, 0xa1b23c4d) else '>'
    div = 1e9 if magic in (0xa1b23c4d, 0x4d3cb2a1) else 1e6
    off = 24
    while off + 16 <= len(d):
        sec, frac, caplen, _ = struct.unpack(e + 'IIII', d[off:off + 16])
        off += 16
        ip = d[off + 14:off + caplen]
        off += caplen
        if ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        tcp = ip[(ip[0] & 15) * 4:]
        sp, dp = struct.unpack('>HH', tcp[:4])
        doff = (tcp[12] >> 4) * 4
        opts, tsval, i = tcp[20:doff], None, 0
        while i < len(opts):
            k = opts[i]
            if k == 0:
                break
            if k == 1:
                i += 1
                continue
            if k == 8:
                tsval = struct.unpack('>I', opts[i + 2:i + 6])[0]
            i += opts[i + 1]
        yield dict(t=sec + frac / div,
                   src='.'.join(map(str, ip[12:16])),
                   sp=sp, dp=dp, tsval=tsval, pay=tcp[doff:])



conns = defaultdict(list)
for p in packets(PCAP):
    key = p['sp'] if p['src'] == NAT else p['dp']
    conns[key].append(p)

rows = []
for port, ps in conns.items():
    cli = [p for p in ps if p['src'] == NAT]
    req = b''.join(p['pay'] for p in cli)
    first_ts = next(((p['t'], p['tsval']) for p in cli if p['tsval'] is not None), None)
    rows.append(dict(
        port=port,
        ts=first_ts,
        line=req.split(b'\r\n')[0].decode(errors='replace'),
        xtrace=[(int(n), h.decode()) for n, h in
                re.findall(rb'X-Trace: *(\d+)-([0-9a-fA-F]{6})', req)]))

T0 = min(p['t'] for ps in conns.values() for p in ps)
with_ts = [r for r in rows if r['ts']]
print(f'Connections: {len(rows)}  with TSval: {len(with_ts)}  whitout TSval: {len(rows) - len(with_ts)}')



anchor = next(r for r in rows if r['line'].startswith('POST /admin/login'))
t_a, v_a = anchor['ts']
print(f'Anchor: port {anchor["port"]}  t = {t_a - T0:.1f} s  TSval = {v_a}')



slopes = {r['port']: (r['ts'][1] - v_a) / (r['ts'][0] - t_a)
          for r in with_ts if r is not anchor}
hist = Counter(round(s) for s in slopes.values())
hz = hist.most_common(1)[0][0]
print(f'Most frequent slopes: {hist.most_common(4)}')
print(f'hz of admin PC = {hz} tick/s')



def residual(r):
    t, v = r['ts']
    return v - (v_a + hz * (t - t_a))


admin = sorted((r for r in with_ts if abs(residual(r)) < 0.2 * hz), key=lambda r: r['ts'][0])
print(f'Connections on the line of\'admin: {len(admin)}')
for r in admin:
    print(f"         port {r['port']}  t={r['ts'][0] - T0:7.1f}s  TSval={r['ts'][1]}  "
          f"residue={residual(r):+5.0f}  {r['line'][:28]:28} {r['xtrace']}")



pieces = {}
for r in admin:
    for n, h in r['xtrace']:
        assert pieces.setdefault(n, h) == h, f'piece {n} in conflict'
assert sorted(pieces) == list(range(1, 9)), 'pieces are missing'

print('Pieces:', ' '.join(f'{n}:{pieces[n]}' for n in range(1, 9)))
print('FLAG: netsec{' + ''.join(pieces[n] for n in range(1, 9)) + '}')
