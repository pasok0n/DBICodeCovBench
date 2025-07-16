#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage: $0 <output_dir> <target_binary> [target_args...]"
    echo "Example: $0 <output_dir> /path/to/app arg1 arg2"
    exit 1
fi

OUTDIR=$1
TARGET_BINARY=$2
shift 2
APPNAME=$(basename "$TARGET_BINARY")

DRRUN=${DYNAMORIO}"/bin64/drrun"
CLIENT=${DYNAMORIO}"/tools/lib64/release/libdrcov.so"

CMD="$DRRUN -c $CLIENT -logdir ${WORKDIR}/$OUTDIR/ -dump_text -- $TARGET_BINARY $*"

echo "Executing: $CMD"
$CMD
RET=$?
if [ $RET -ne 0 ]; then
    echo "Launch failed with return code $RET"
    exit 1
fi

echo "Process launched with drcov client. Coverage data will be"
echo "written when the target terminates. Look for log files matching:"
echo "drcov.${APPNAME}.*.proc.log"
