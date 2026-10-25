
## baseline.json: verified 6 runs

| Image | Phase | Docker MiB median [min,max] | RSS sum MiB | PSS sum MiB |
|---|---|---:|---:|---:|
| zeek-monitor:memory-optimized | idle | 58.31 [57.67,58.52] | 123.81 [123.55,123.93] | 121.09 [120.86,121.21] |
| zeek-monitor:memory-optimized | monitored_2000 | 59.86 [59.84,60.23] | 125.97 [125.71,126.09] | 123.24 [123.03,123.34] |
| zeek-monitor:memory-optimized | plus_unmonitored_10000 | 80.46 [80.10,80.52] | 146.30 [146.18,146.33] | 143.59 [143.46,143.61] |
| rust-pcap-log:test | idle | 1.23 [1.15,1.39] | 11.28 [11.23,11.37] | 10.43 [10.42,10.51] |
| rust-pcap-log:test | monitored_2000 | 1.79 [1.78,1.80] | 12.19 [12.14,12.27] | 11.32 [11.29,11.42] |
| rust-pcap-log:test | plus_unmonitored_10000 | 1.79 [1.78,1.79] | 12.19 [12.14,12.27] | 11.33 [11.27,11.43] |
zeek-monitor:memory-optimized process CPU seconds: [0.17000000000000004, 0.15999999999999992, 0.18999999999999995] median 0.17000000000000004 measurement wall seconds [8.546064869005932, 8.844985850002558, 8.851398376005818] paced sender packets/sec [13597.211023471524, 13842.76841345443, 12769.97293083387]
rust-pcap-log:test process CPU seconds: [0.04999999999999999, 0.06, 0.07] median 0.06 measurement wall seconds [7.693491562000418, 8.491661448999366, 7.469579854994663] paced sender packets/sec [14456.109132445898, 13532.818086130523, 13593.856589114685]

## extended.json: verified 6 runs

| Image | Phase | Docker MiB median [min,max] | RSS sum MiB | PSS sum MiB |
|---|---|---:|---:|---:|
| zeek-monitor:memory-optimized | idle | 58.18 [57.93,58.25] | 123.52 [123.25,123.70] | 120.90 [120.48,121.02] |
| zeek-monitor:memory-optimized | high_20000 | 96.17 [96.16,96.17] | 161.93 [161.66,162.12] | 159.27 [158.92,159.39] |
| zeek-monitor:memory-optimized | expired_high | 97.24 [97.15,98.05] | 162.46 [162.16,163.26] | 159.82 [159.43,160.55] |
| zeek-monitor:memory-optimized | cycle_1_active | 96.61 [96.59,97.20] | 162.46 [162.16,163.26] | 159.86 [159.41,160.58] |
| zeek-monitor:memory-optimized | cycle_1_expired | 97.29 [96.64,97.65] | 162.46 [162.16,163.30] | 159.84 [159.40,160.60] |
| zeek-monitor:memory-optimized | cycle_2_active | 96.59 [96.56,97.24] | 162.46 [162.16,163.30] | 159.79 [159.41,160.58] |
| zeek-monitor:memory-optimized | cycle_2_expired | 96.95 [96.56,97.79] | 162.46 [162.16,163.32] | 159.86 [159.39,160.63] |
| zeek-monitor:memory-optimized | cycle_3_active | 96.60 [96.57,97.26] | 162.46 [162.16,163.32] | 159.82 [159.39,160.62] |
| zeek-monitor:memory-optimized | cycle_3_expired | 96.96 [96.94,97.45] | 162.46 [162.16,163.33] | 159.81 [159.40,160.62] |
| rust-pcap-log:test | idle | 1.15 [0.98,1.43] | 11.34 [11.27,11.38] | 10.48 [10.43,10.51] |
| rust-pcap-log:test | high_20000 | 8.50 [8.50,8.77] | 18.95 [18.88,18.98] | 18.08 [18.05,18.12] |
| rust-pcap-log:test | expired_high | 4.52 [3.08,4.96] | 14.61 [13.09,14.64] | 13.72 [12.23,13.82] |
| rust-pcap-log:test | cycle_1_active | 4.17 [2.72,4.17] | 14.61 [13.09,14.64] | 13.73 [12.27,13.76] |
| rust-pcap-log:test | cycle_1_expired | 4.29 [2.84,4.53] | 14.61 [13.09,14.64] | 13.72 [12.25,13.78] |
| rust-pcap-log:test | cycle_2_active | 4.17 [2.73,4.18] | 14.61 [13.09,14.64] | 13.72 [12.24,13.78] |
| rust-pcap-log:test | cycle_2_expired | 4.24 [2.73,4.55] | 14.61 [13.09,14.64] | 13.77 [12.25,13.78] |
| rust-pcap-log:test | cycle_3_active | 4.17 [2.72,4.23] | 14.61 [13.09,14.64] | 13.72 [12.27,13.78] |
| rust-pcap-log:test | cycle_3_expired | 4.16 [2.74,4.36] | 14.61 [13.09,14.64] | 13.74 [12.26,13.80] |
zeek-monitor:memory-optimized process CPU seconds: [6.13, 2.72, 2.74] median 2.74 measurement wall seconds [73.30286649900518, 72.75242579000042, 72.79149568499997] paced sender packets/sec [13696.219093687849, 13967.579433421712, 13882.598340223443]
rust-pcap-log:test process CPU seconds: [0.85, 0.8400000000000001, 0.8999999999999999] median 0.85 measurement wall seconds [72.60740110399638, 72.26965871200082, 72.70875394000177] paced sender packets/sec [14098.732839349223, 13902.61983141737, 13754.113906388931]
