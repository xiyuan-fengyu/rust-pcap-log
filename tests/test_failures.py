import unittest,tempfile,time,json
from pathlib import Path
from common import *
ROOT=Path(__file__).parent/'fixtures'
OUT=Path('.artifacts/failures');OUT.mkdir(parents=True,exist_ok=True)
class Failures(unittest.TestCase):
    def offline(self,name,settings=None,command=None):
        return docker('run','--rm','--network','none','--cap-drop','ALL','--read-only','--tmpfs','/tmp','-v',f'{ROOT.resolve()}:/fixtures:ro',*env({'LISTEN_0':'tcp 100.64.0.20 443,8000-8100','LISTEN_1':'udp 100.64.0.20 1234'}|(settings or {})),*(['--entrypoint','sh'] if command else []),IMAGE,*( ['-c',command] if command else ['--read-pcap',f'/fixtures/{name}.pcap']),check=False,timeout=15)
    def test_session_limit_no_eviction_as_complete_record(self):
        p=self.offline('sessions',{'MAX_SESSIONS':'1'})
        self.assertNotEqual(p.returncode,0);self.assertIn('session_limit=1',p.stderr);self.assertEqual(p.stdout,'')
        (OUT/'session-limit.json').write_text(json.dumps({'stdout':p.stdout,'stderr':p.stderr,'exit':p.returncode},indent=2)+'\n')
    def test_fragment_limit_no_fake_session(self):
        from generate_pcaps import packet,write,fragments,checksum,SRC,DST
        import struct
        frame=packet(SRC,DST,52000,1234,'udp',b'x'*32)[0]
        a,_=fragments(frame);b=bytearray(a);b[18:20]=struct.pack('!H',124);b[24:26]=b'\0\0';b[24:26]=struct.pack('!H',checksum(b[14:34]))
        write('fragment_limit',[(0,a),(.1,bytes(b))])
        p=self.offline('fragment_limit',{'MAX_FRAGMENTS':'1'})
        self.assertNotEqual(p.returncode,0);self.assertEqual(p.stdout,'');self.assertIn('fragment_limit=1',p.stderr)
        (OUT/'fragment-limit.json').write_text(json.dumps({'stderr':p.stderr,'exit':p.returncode},indent=2)+'\n')
    def test_unwritable_log_path(self):
        p=self.offline('sessions',{'LOG_FILE':'/readonly/log.txt'})
        self.assertNotEqual(p.returncode,0);self.assertEqual(p.stdout,'');self.assertIn('Read-only file system',p.stderr)
        (OUT/'unwritable-path.json').write_text(json.dumps({'stderr':p.stderr,'exit':p.returncode},indent=2)+'\n')
    def test_output_write_failure(self):
        p=self.offline('sessions',command='exec rust-pcap-log --read-pcap /fixtures/sessions.pcap > /dev/full')
        self.assertNotEqual(p.returncode,0);self.assertIn('log write failed',p.stderr);self.assertEqual(p.stdout,'')
        (OUT/'write-error.json').write_text(json.dumps({'stderr':p.stderr,'exit':p.returncode},indent=2)+'\n')
    def test_blocked_output_has_deadline(self):
        start=time.monotonic()
        p=self.offline('sessions',{'SHUTDOWN_TIMEOUT':'1','LOG_FORMAT':'X'*60000},command='mkfifo /tmp/out; sleep 30 < /tmp/out & exec rust-pcap-log --read-pcap /fixtures/sessions.pcap > /tmp/out')
        elapsed=time.monotonic()-start
        self.assertNotEqual(p.returncode,0);self.assertIn('deadline exceeded',p.stderr);self.assertLess(elapsed,10)
        (OUT/'blocked-output.json').write_text(json.dumps({'stderr':p.stderr,'exit':p.returncode,'elapsed':elapsed},indent=2)+'\n')
    def test_fifo_log_rejected_without_waiting(self):
        p=self.offline('sessions',{'LOG_FILE':'/tmp/logfifo'},command='mkfifo /tmp/logfifo; exec rust-pcap-log --read-pcap /fixtures/sessions.pcap')
        self.assertNotEqual(p.returncode,0);self.assertEqual(p.stdout,'')
    def test_local_discovery_failure_and_empty_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='rpl-ifaddrs-') as directory:
            path=Path(directory)
            (path/'fail.c').write_text('#include <ifaddrs.h>\n#include <errno.h>\n#include <stdlib.h>\nint getifaddrs(struct ifaddrs **p) { *p=0; if (getenv("EMPTY_DISCOVERY")) return 0; errno=EIO; return -1; }\n')
            docker('run','--rm','--network','none','--cap-drop','ALL','--read-only','--tmpfs','/tmp','-v',f'{directory}:/scratch','--entrypoint','cc',os.environ.get('RUST_BUILD_IMAGE','rust-pcap-log:build-test'),'-shared','-fPIC','/scratch/fail.c','-o','/scratch/fail.so')
            results=[]
            for empty in [False,True]:
                values={'LISTEN_0':'udp 0.0.0.0 1234','LD_PRELOAD':'/scratch/fail.so'}
                if empty:values['EMPTY_DISCOVERY']='1'
                p=docker('run','--rm','--network','none','--cap-drop','ALL','--read-only','-v',f'{directory}:/scratch:ro',*env(values),IMAGE,'--check-config',check=False)
                self.assertNotEqual(p.returncode,0);self.assertEqual(p.stdout,'');self.assertIn('fatal:',p.stderr)
                if empty:self.assertIn('refusing wildcard',p.stderr)
                results.append({'empty':empty,'exit':p.returncode,'stderr':p.stderr})
            (OUT/'discovery-fail-closed.json').write_text(json.dumps(results,indent=2)+'\n')
    def test_invalid_ip_checksum_rejected_before_session(self):
        # This is a separate layer from invalid TCP/UDP checksums, which Zeek
        # can represent as a zero-byte session.
        from generate_pcaps import packet,write,SRC,DST
        frame=bytearray(packet(SRC,DST,52000,1234,'udp',b'abc')[0]);frame[24]^=1;write('bad_ip_checksum',[(0,bytes(frame))])
        p=self.offline('bad_ip_checksum',{'IGNORE_CHECKSUMS':'false'});self.assertEqual(p.returncode,0);self.assertEqual(p.stdout,'');self.assertIn('checksum_rejected=1',p.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
