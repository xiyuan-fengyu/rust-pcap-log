"""Offline 10k TCP SYN states, three creation/expiry cycles; NOT live TCP load."""
import json,sys
from collections import Counter
from pathlib import Path
from generate_pcaps import write,packet,SRC,DST
from differential import run,OLD,NEW

def main():
    frames=[]
    for cycle in range(3):
        for i in range(10000):
            frame=packet(SRC,DST,20000+i,443,'tcp',seq=100,flags=2)[0]
            frames.append((cycle*10+i/1e6,frame))
    write('tcp_10000_cycles',frames)
    old=run(OLD,'tcp_10000_cycles');new=run(NEW,'tcp_10000_cycles')
    expected=Counter({f'{SRC}|{20000+i}|TCP|40|0|0.000|{DST}|443':3 for i in range(10000)})
    out={'old':old,'new':new,'expected_records':30000,'old_exact':old['exit']==0 and Counter(old['stdout'].splitlines())==expected,'new_exact':new['exit']==0 and Counter(new['stdout'].splitlines())==expected}
    Path('.artifacts/differential/tcp-cycles.json').write_text(json.dumps(out,indent=2)+'\n')
    print({k:v for k,v in out.items() if k not in ('old','new')})
    if not out['old_exact'] or not out['new_exact']:sys.exit(1)
if __name__=='__main__':main()
