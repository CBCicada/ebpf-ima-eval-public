#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

python3 run.py --timeout-ms 10000 --holder-seconds 45
python3 run.py --populated --timeout-ms 10000 --holder-seconds 45

python3 analyze.py results
