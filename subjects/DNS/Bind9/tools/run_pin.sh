#!/bin/bash

# Set these to your actual Pin installation path if not already set
TOOL=${PIN}"/source/tools/MyPinTool/obj-intel64/pin_cov.so"

OUTDIR=$1

if [ "$2" = "-pid" ]; then
    PID=$3
    CMD=${PIN}"/pin -pid $PID -t $TOOL -o ${WORKDIR}/${OUTDIR}/pin_coverage_inject.log"
elif [ "$2" = "--" ]; then
    shift 2
    CMD=${PIN}"/pin -t $TOOL -o ${WORKDIR}/${OUTDIR}/pin_coverage_spawn.log -- $*"
fi

echo "Executing: $CMD"
exec $CMD
