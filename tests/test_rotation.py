"""Container rotation tests with an injected wall clock (never change the host clock)."""
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from common import docker, env, identifier, ready, remove, traffic, until, IMAGE

OUT = Path('.artifacts/rotation')
OUT.mkdir(parents=True, exist_ok=True)

CLOCK_SOURCE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <dlfcn.h>
time_t time(time_t *out) {
    const char *path = getenv("RPL_TEST_CLOCK");
    FILE *f = path ? fopen(path, "r") : NULL;
    long long value;
    if (f && fscanf(f, "%lld", &value) == 1) {
        fclose(f);
        if (out) *out = (time_t)value;
        return (time_t)value;
    }
    if (f) fclose(f);
    time_t (*real_time)(time_t *) = dlsym(RTLD_NEXT, "time");
    return real_time(out);
}
'''


class Rotation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='rpl-clock-')
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.clock_dir = Path(cls.scratch.name)
        (cls.clock_dir / 'clock.c').write_text(CLOCK_SOURCE)
        docker('run', '--rm', '--network', 'none', '--cap-drop', 'ALL', '--read-only', '--tmpfs', '/tmp',
               '-v', f'{cls.clock_dir}:/clock', '--entrypoint', 'cc',
               os.environ.get('RUST_BUILD_IMAGE', 'rust-pcap-log:build-test'),
               '-shared', '-fPIC', '/clock/clock.c', '-o', '/clock/clock.so', '-ldl')

    def live_boundary(self, zone, suffix, archive_name, stream=False):
        name = identifier()
        # UTC and Shanghai have different midnight instants.
        hour = 15 if zone == 'Asia/Shanghai' else 23
        before = int(datetime(2026, 10, 25, hour, 59, 59, tzinfo=timezone.utc).timestamp())
        with tempfile.TemporaryDirectory(prefix='rpl-daily-') as directory:
            root = Path(directory)
            log = root / 'access.log'
            log.write_text('before midnight\n')
            os.utime(log, (before, before))
            archive = root / archive_name
            archive.write_text('existing archive\n')
            clock = root / 'now'
            clock.write_text(str(before))
            settings = {'LISTEN_0': 'udp 127.0.0.1 19181', 'CAPTURE_INTERFACE': 'lo',
                        'LOG_FILE': '/dev/stdout' if stream else '/logs/access.log',
                        'LOG_ROTATE_SUFFIX': suffix, 'TZ': zone,
                        'UDP_INACTIVITY_TIMEOUT': '1', 'STATS_INTERVAL': '1',
                        'LD_PRELOAD': '/clock/clock.so', 'RPL_TEST_CLOCK': '/logs/now'}
            try:
                args = ['run', '-d', '--name', name, '--network', 'none', '--cap-drop', 'ALL',
                        '--cap-add', 'NET_RAW', '--read-only', '-v', f'{directory}:/logs',
                        '-v', f'{self.clock_dir}:/clock:ro', *env(settings)]
                if stream:
                    args += ['--entrypoint', 'sh', IMAGE, '-c', 'exec rust-pcap-log >> /logs/access.log']
                else:
                    args += [IMAGE]
                docker(*args)
                ready(name)
                self.assertEqual(log.read_text(), 'before midnight\n')
                # Atomic clock update; the capture loop must rotate without traffic.
                (root / 'next').write_text(str(before + 1))
                (root / 'next').replace(clock)
                if not stream:
                    until(lambda: Path(str(archive) + '.1').exists() and log.exists())
                    self.assertEqual(Path(str(archive) + '.1').read_text(), 'before midnight\n')
                    self.assertEqual(log.read_text(), '')
                traffic(name, 19181, 1)
                until(lambda: 'UDP' in log.read_text())
                docker('stop', '--time', '20', name)
                state = json.loads(docker('inspect', name).stdout)[0]['State']
                stderr = docker('logs', name).stderr
                self.assertEqual(state['ExitCode'], 0, stderr)
                self.assertIn('2026-10-26T00:00:00', log.read_text())
                self.assertEqual(archive.read_text(), 'existing archive\n')
                if stream:
                    self.assertTrue(log.read_text().startswith('before midnight\n'))
                    self.assertNotIn('log rotated:', stderr)
                    self.assertFalse(Path(str(archive) + '.1').exists())
                else:
                    self.assertEqual(stderr.count('log rotated:'), 1)
                (OUT / f'{zone.replace("/", "-")}-{stream}.json').write_text(json.dumps({
                    'clock': 'LD_PRELOAD time() override; monotonic capture clock unchanged',
                    'settings': settings, 'exit': state['ExitCode'], 'stderr': stderr,
                    'active': log.read_text(),
                    'files': sorted(p.name for p in root.iterdir())}, indent=2) + '\n')
            finally:
                remove(name)

    def test_idle_midnight_utc_default_suffix_and_collision(self):
        self.live_boundary('UTC', '.%Y%m%d', 'access.log.20261025')

    def test_idle_midnight_shanghai_custom_suffix_and_collision(self):
        self.live_boundary('Asia/Shanghai', '.%Y-%m-%d.bak', 'access.log.2026-10-25.bak')

    def test_redirected_stdout_does_not_rotate(self):
        self.live_boundary('UTC', '.%Y%m%d', 'access.log.20261025', stream=True)

    def test_startup_old_file_and_invalid_suffix(self):
        with tempfile.TemporaryDirectory(prefix='rpl-restart-') as directory:
            root = Path(directory)
            log = root / 'access.log'
            log.write_text('old process\n')
            stamp = int(datetime(2020, 1, 2, 12, tzinfo=timezone.utc).timestamp())
            os.utime(log, (stamp, stamp))
            result = docker('run', '--rm', '--network', 'none', '--cap-drop', 'ALL', '--read-only',
                            '-v', f'{directory}:/logs', '-v', f'{Path("tests/fixtures").resolve()}:/fixtures:ro',
                            *env({'LISTEN_0': 'udp 100.64.0.20 1234', 'LOG_FILE': '/logs/access.log'}),
                            IMAGE, '--read-pcap', '/fixtures/sessions.pcap')
            self.assertEqual((root / 'access.log.20200102').read_text(), 'old process\n')
            self.assertIn('UDP', log.read_text())
            self.assertIn('log rotated:', result.stderr)
        for suffix in ['', '%Q', '../%Y', '%n']:
            result = docker('run', '--rm', '--network', 'none', '--cap-drop', 'ALL', '--read-only',
                            *env({'LISTEN_0': 'udp 127.0.0.1 1234', 'LOG_ROTATE_SUFFIX': suffix}),
                            IMAGE, '--check-config', check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('LOG_ROTATE_SUFFIX', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
