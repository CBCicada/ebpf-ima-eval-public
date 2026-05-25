#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

python3 run.py --progs 1 --prog-pins 1 --timeout-ms 10000 --holder-seconds 45

python3 run.py --progs 1 --prog-pins 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 10 --prog-pins 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 50 --prog-pins 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 100 --prog-pins 1 --timeout-ms 10000 --holder-seconds 45

python3 run.py --progs 1 --prog-pins 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-pins 10 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-pins 100 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-pins 1000 --timeout-ms 10000 --holder-seconds 45

python3 run.py --progs 1 --prog-fd-holders 1 --fds-per-holder 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-fd-holders 10 --fds-per-holder 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-fd-holders 50 --fds-per-holder 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-fd-holders 100 --fds-per-holder 1 --timeout-ms 10000 --holder-seconds 45

python3 run.py --progs 1 --prog-fd-holders 1 --fds-per-holder 10 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-fd-holders 1 --fds-per-holder 100 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-fd-holders 1 --fds-per-holder 1000 --timeout-ms 10000 --holder-seconds 45

python3 run.py --progs 1 --prog-array-entries 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-array-entries 10 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-array-entries 100 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --prog-array-entries 1000 --timeout-ms 10000 --holder-seconds 45

python3 run.py --progs 1 --link-count 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --link-count 5 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --link-count 10 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --link-count 18 --timeout-ms 10000 --holder-seconds 45

python3 run.py --progs 1 --link-pins 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --link-pins 5 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --link-pins 10 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --link-pins 18 --timeout-ms 10000 --holder-seconds 45

python3 run.py --progs 1 --link-pins 10 --link-pin-fd-holders 1 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --link-pins 10 --link-pin-fd-holders 10 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 1 --link-pins 10 --link-pin-fd-holders 50 --timeout-ms 10000 --holder-seconds 45

python3 run.py --progs 10 --prog-pins 10 --prog-fd-holders 10 --fds-per-holder 2 --prog-array-entries 100 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 4 --prog-pins 2 --prog-fd-holders 3 --fds-per-holder 2 --pin-fd-holders 2 --prog-array-entries 32 --link-count 4 --link-fd-holders 3 --link-pins 4 --link-pin-fd-holders 2 --timeout-ms 10000 --holder-seconds 45
python3 run.py --progs 10 --link-count 10 --link-pins 8 --timeout-ms 10000 --holder-seconds 45

python3 analyze.py results
