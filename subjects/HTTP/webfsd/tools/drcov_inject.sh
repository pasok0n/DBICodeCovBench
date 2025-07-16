#!/bin/bash
if [ $# -ne 2 ]; then
    echo "Usage: $0 <pid>"
    exit 1
fi

OUTDIR=$1
PID="$2"
APPNAME=$(cat /proc/$PID/comm 2>/dev/null)
if [ -z "$APPNAME" ]; then
    echo "Unable to determine application name from pid $PID"
    exit 1
fi

DRRUN=${DYNAMORIO}"/bin64/drrun"
CLIENT="/home/ubuntu/coverage_instrumentation/build/libcoverage_client.so"

CMD="$DRRUN -attach $PID -c $CLIENT -target_module webfsd -target_function main"
echo "Executing: $CMD"
$CMD
RET=$?
if [ $RET -ne 0 ]; then
    echo "Injection failed with return code $RET"
    exit 1
fi

echo "Injection complete. The drcov client was active in process $PID."
