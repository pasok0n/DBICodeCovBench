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
CLIENT=${DYNAMORIO}"/tools/lib64/release/libdrcov.so"

CMD="$DRRUN -attach $PID -c $CLIENT -dump_text -logdir ${WORKDIR}/$OUTDIR/"
echo "Executing: $CMD"
$CMD
RET=$?
if [ $RET -ne 0 ]; then
    echo "Injection failed with return code $RET"
    exit 1
fi

echo "Injection complete. The drcov client was active in process $PID."
