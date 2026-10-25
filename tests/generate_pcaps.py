"""Deterministic standard-library PCAPs. Payload only exists in test artifacts."""
from pathlib import Path
import struct, sys, json
sys.path.insert(0,str(Path(__file__).parent/'reference'))
from pcap_fixture import packet, checksum, create, LISTEN, FORMAT
ROOT=Path(__file__).parent/'fixtures'
SRC='100.64.0.11'; DST='100.64.0.20'
def write(name,frames,link=1):
    with (ROOT/(name+'.pcap')).open('wb') as f:
        f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,262144,link))
        for t,frame,*wire in frames:
            micros=round(t*1e6)
            f.write(struct.pack('<IIII',1700000000+micros//1000000,micros%1000000,len(frame),wire[0] if wire else len(frame)));f.write(frame)
def tcp(flags,seq=100,ack=0,reverse=False,payload=b'',port=52000):
    return packet(DST,SRC,443,port,'tcp',payload,seq,ack,flags)[0] if reverse else packet(SRC,DST,port,443,'tcp',payload,seq,ack,flags)[0]
def fragments(frame,v6=False):
    eth=frame[:14];ip=frame[14:];hl=40 if v6 else 20;data=ip[hl:];out=[]
    for offset,part,more in [(0,data[:16],True),(16,data[16:],False)]:
        if v6:
            h=ip[:4]+struct.pack('!H',len(part)+8)+bytes([44])+ip[7:40]
            h+=struct.pack('!BBHI',ip[6],0,offset|int(more),123)
        else:
            h=bytearray(ip[:20]);struct.pack_into('!H',h,2,20+len(part));struct.pack_into('!H',h,4,123);struct.pack_into('!H',h,6,offset//8|(0x2000 if more else 0));h[10:12]=b'\0\0';struct.pack_into('!H',h,10,checksum(h))
        out.append(eth+bytes(h)+part)
    return out
def generate():
    ROOT.mkdir(parents=True,exist_ok=True);create(ROOT)
    cases={}
    def case(name,frames,link=1,mode='equal',note='',env=None):
        write(name,frames,link);cases[name]={'mode':mode,'note':note,'env':env or {}}
    case('partial',[(i*.1,f)for i,f in enumerate([
        packet(SRC,DST,52001,1234,'udp',b'x')[0],packet('2001:db8::11','2001:db8::20',52002,1234,'udp',b'x')[0],
        tcp(2,port=52003),tcp(24,ack=200,payload=b'hello',port=52004),tcp(2,port=52005),tcp(2,port=52005),tcp(20,ack=101,reverse=True,port=52005)])])
    handshake=[(0,tcp(2)),(.1,tcp(18,200,101,True)),(.2,tcp(16,101,201))]
    case('half_close',handshake+[(.3,tcp(17,101,201)),(.5,tcp(24,201,102,True,b'still sending')),(.6,tcp(16,102,214))])
    case('full_close',handshake+[(.3,tcp(17,101,201)),(.4,tcp(16,201,102,True)),(.5,tcp(17,201,102,True)),(.6,tcp(16,102,202)),(.7,tcp(16,102,202))])
    case('rst_tail',handshake+[(.3,tcp(20,201,101,True)),(.4,tcp(16,101,201)),(.5,tcp(4,101,201))])
    case('retransmit',handshake+[(.3,tcp(24,101,201,payload=b'abc')),(.4,tcp(24,101,201,payload=b'abc')),(.5,tcp(16,201,104,True))])
    case('syn_reuse',[(0,tcp(2)),(.2,tcp(2)),(.3,tcp(2,1000)),(.4,tcp(18,2000,1001,True))])
    case('closed_reuse',handshake+[(.3,tcp(17,101,201)),(.4,tcp(17,201,102,True)),(.5,tcp(16,102,202)),(.7,tcp(2,1000)),(.8,tcp(18,2000,1001,True))])
    case('midstream_syn_reuse',[(0,tcp(24,100,200,payload=b'abc')),(.2,tcp(2,1000))])
    case('syn_timeout',[(0,tcp(2)),(4,tcp(2)),(7,tcp(2)),(8,tcp(20,ack=101,reverse=True))])
    case('tcp_idle_timeout',[(0,tcp(24,100,200,payload=b'a')),(302,tcp(24,101,200,payload=b'b'))])
    u=packet(SRC,DST,52000,1234,'udp',b'x'*32)[0]
    v=packet('2001:db8::11','2001:db8::20',52000,1234,'udp',b'x'*32)[0]
    case('udp_timeout',[(0,u),(61,u)])
    a,b=fragments(u)
    atomic=v[:18]+struct.pack('!H',len(v)-54+8)+b'\x2c'+v[21:54]+struct.pack('!BBHI',17,0,0,99)+v[54:]
    case('ipv6_atomic_fragment',[(0,atomic)])
    case('fragment_duration',[(0,a),(.1,b),(1,u)])
    case('synack_unfinished',[(0,tcp(2)),(.1,tcp(18,200,101,True)),(7,tcp(16,101,201))])
    case('ack_midstream_tail',[(0,tcp(16,100,200)),(.2,tcp(16,100,200))])
    case('rst_repeat_tail',[(0,tcp(4,100)),(.2,tcp(4,100))])
    case('synack_first',[(0,tcp(18,200,101,True)),(.1,tcp(16,101,201))])
    for name,frame,v6 in [('ipv4',u,False),('ipv6',v,True)]:
        a,b=fragments(frame,v6)
        case(name+'_fragments',[(0,a),(.1,b)])
        case(name+'_out_of_order',[(0,b),(.1,a)])
        case(name+'_duplicate',[(0,a),(.05,a),(.1,b)])
        case(name+'_missing_first',[(0,b)])
        conflict=bytearray(a);conflict[-1]^=1
        case(name+'_conflict',[(0,a),(.05,bytes(conflict)),(.1,b)],note='first-arrival bytes win; overlap diagnostics retained')
    a,b=fragments(u)
    case('fragment_expiry',[(0,a),(301,b)])
    # A non-copied IPv4 option only appears in the first fragment.
    first=bytearray(a[:34]+b'\x01'*4+a[34:]);first[14]=0x46;first[16:18]=struct.pack('!H',len(first)-14);first[24:26]=b'\0\0';first[24:26]=struct.pack('!H',checksum(first[14:38]))
    case('ipv4_fragment_options',[(0,b),(.1,bytes(first))])
    case('ipv4_fragment_options_ordered',[(0,bytes(first)),(.1,b)])
    tf=tcp(24,100,200,payload=b'x'*32);ta,tb=fragments(tf);case('tcp_fragments',[(0,tb),(.1,ta)])
    # IPv6 destination option in the fragmentable portion.
    post=v[:18]+struct.pack('!H',len(v)-54+8)+b'\x3c'+v[21:54]+bytes([17,0,0,0,0,0,0,0])+v[54:]
    pa,pb=fragments(post,True);case('ipv6_fragment_extension_after',[(0,pb),(.1,pa)])
    # IPv6 hop-by-hop option precedes fragment header (unfragmentable part).
    va,vb=fragments(v,True);expanded=[]
    for f in [va,vb]:
        h=f[:18]+struct.pack('!H',len(f)-54+8)+b'\0'+f[21:54]+bytes([44,0,0,0,0,0,0,0])+f[54:]
        expanded.append(h)
    case('ipv6_fragment_extension_before',[(0,expanded[1]),(.1,expanded[0])])
    # Extension headers BEFORE UDP; transport pseudoheader checksum unchanged.
    ext=v[:18]+struct.pack('!H',len(v)-54+16)+b'\0'+v[21:54]+bytes([60,0,0,0,0,0,0,0])+bytes([17,0,0,0,0,0,0,0])+v[54:]
    case('ipv6_extensions',[(0,ext)])
    case('vlan',[(0,u[:12]+struct.pack('!HH',0x8100,123)+u[12:])])
    case('qinq',[(0,u[:12]+struct.pack('!HHHH',0x88a8,7,0x8100,123)+u[12:])])
    case('sll',[(0,struct.pack('!HHH8sH',0,1,6,b'\0'*8,0x800)+u[14:])],113)
    case('sll2',[(0,struct.pack('!HHIHBB8s',0x800,0,1,1,0,6,b'\0'*8)+u[14:])],276)
    case('raw',[(0,u[14:])],101)
    case('truncated',[(0,u[:40],len(u))],mode='gate',note='fail closed on missing IP bytes')
    bad=bytearray(u);bad[16:18]=b'\0\x10'
    case('malformed',[(0,bytes(bad))],mode='gate',note='invalid total IP length')
    bad=bytearray(u);bad[-1]^=1
    case('bad_checksum',[(0,bytes(bad))],mode='checksum',note='Zeek creates a zero-byte session for invalid L4 checksum')
    for proto in ['udp','tcp']:
        good=packet(SRC,DST,52000,1234 if proto=='udp' else 443,proto,b'abc',100,0,2 if proto=='tcp' else 0)[0]
        broken=bytearray(good);broken[-1]^=1;broken=bytes(broken)
        for suffix,frames in [('bad',[(0,broken)]),('bad_first',[(0,broken),(1,good)]),('bad_last',[(0,good),(1,broken)]),('bad_both',[(0,broken),(1,broken)])]:
            case(proto+'_'+suffix,frames)
    # Explicit unsupported tunnel compatibility gate.
    outer=bytearray(u[:34]);outer[23]=4;outer[16:18]=struct.pack('!H',20+len(u)-14);outer[24:26]=b'\0\0';outer[24:26]=struct.pack('!H',checksum(outer[14:34]))
    case('ipip',[(0,bytes(outer)+u[14:])])
    for name,proto,body in [('gre',47,b'\0\0\x08\x00'+u[14:]),('gre_ethernet',47,b'\0\0\x65\x58'+u)]:
        h=bytearray(u[:34]);h[23]=proto;h[16:18]=struct.pack('!H',20+len(body));h[24:26]=b'\0\0';h[24:26]=struct.pack('!H',checksum(h[14:]));case(name,[(0,bytes(h)+body)])
    vx=packet('192.0.2.1','192.0.2.2',40000,4789,'udp',b'\x08'+b'\0'*7+u)[0]
    case('vxlan',[(0,vx)],env={'LISTEN_99':'udp 192.0.2.2 4789'})
    geneve=packet('192.0.2.1','192.0.2.2',40000,6081,'udp',struct.pack('!BBH3sB',0,0,0x6558,b'\0\0\1',0)+u)[0]
    case('geneve_gate',[(0,geneve)],mode='gate',note='Geneve is not yet implemented; fail closed')
    a,b=fragments(u);h=bytearray(b[:34]);h[20:22]=struct.pack('!H',1);data=bytearray(u[42:]);data[0]^=1
    h[16:18]=struct.pack('!H',20+len(data));h[24:26]=b'\0\0';h[24:26]=struct.pack('!H',checksum(h[14:]));overlap=bytes(h)+bytes(data)
    case('overlap_first_lower',[(0,a),(.1,overlap)])
    case('overlap_first_higher',[(0,overlap),(.1,a)])
    (ROOT/'cases.json').write_text(json.dumps(cases,indent=2)+'\n')
if __name__=='__main__':generate()
