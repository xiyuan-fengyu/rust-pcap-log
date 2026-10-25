"""Strict, field-for-field Zeek 9 / Rust differential; explicit gates not passes."""
import os,json,sys,subprocess,datetime
from pathlib import Path
from generate_pcaps import generate,ROOT,LISTEN,FORMAT
NEW=os.environ.get('RUST_TEST_IMAGE','rust-pcap-log:test')
OLD=os.environ.get('ZEEK_TEST_IMAGE','zeek-monitor:memory-optimized')
OUT=Path('.artifacts/differential');OUT.mkdir(parents=True,exist_ok=True)
def run(image,name,env=None):
    settings=LISTEN|{'LOG_FORMAT':FORMAT,'IGNORE_CHECKSUMS':'false'}|(env or {})
    args=['docker','run','--rm','--network','none','--cap-drop','ALL','--read-only','--tmpfs','/tmp','-v',f'{ROOT.resolve()}:/fixtures:ro']
    for k,v in settings.items():args+=['-e',f'{k}={v}']
    if image==NEW and os.environ.get('RUST_TEST_ENTRYPOINT'):args+=['--entrypoint',os.environ['RUST_TEST_ENTRYPOINT']]
    p=subprocess.run(args+[image,'--read-pcap',f'/fixtures/{name}.pcap'],capture_output=True,text=True,timeout=30)
    return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
def main():
    generate();cases={'sessions':{'mode':'equal'},**json.loads((ROOT/'cases.json').read_text())};report={};failures=[];gates=[]
    for name,case in cases.items():
        old=run(OLD,name,case.get('env'));new=run(NEW,name,case.get('env'));equal=old['exit']==new['exit']==0 and sorted(old['stdout'].splitlines())==sorted(new['stdout'].splitlines())
        record={'case':case,'old':old,'new':new,'equal':equal};report[name]=record
        if case['mode']=='equal':
            if not equal:failures.append(name)
        elif case['mode']=='gate':
            gates.append(name)
            if new['exit']==0 or new['stdout']:failures.append(name)
        elif case['mode']=='checksum':
            if not equal or 'checksum_rejected=1' not in new['stderr']:failures.append(name)
            ignored=run(NEW,name,{'IGNORE_CHECKSUMS':'true'});record['new_ignore_checksums']=ignored
            if ignored['exit']!=0 or not ignored['stdout']:failures.append(name)
        print(name,'EQUAL' if equal else 'GATE' if case['mode']=='gate' else 'DIFFERENT',flush=True)
        if not equal and case['mode']=='equal':print('OLD:',old,'NEW:',new,flush=True)
        (OUT/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    # Output timestamps are WALL clock, not synthetic capture time, +08:00 TZ.
    before=datetime.datetime.now(datetime.timezone.utc);p=run(NEW,'sessions',{'TZ':'Asia/Shanghai','LOG_FORMAT':'${time_iso8601}|$$remote_addr|$protocol'});after=datetime.datetime.now(datetime.timezone.utc)
    assert p['exit']==0,p
    for line in p['stdout'].splitlines():
        ts,literal,proto=line.split('|');t=datetime.datetime.fromisoformat(ts)
        assert t.utcoffset()==datetime.timedelta(hours=8) and before-datetime.timedelta(seconds=1)<=t<=after
        assert literal=='$remote_addr' and proto in ('TCP','UDP')
    (OUT/'wall-clock.json').write_text(json.dumps(p,indent=2)+'\n')
    print(f'{len(cases)} cases; {len(gates)} explicit compatibility gates; failures={failures}')
    if failures:sys.exit(1)
if __name__=='__main__':main()
