#!/bin/bash

DRRUN=${DYNAMORIO}"/bin64/drrun"
CLIENT=${DYNAMORIO}"/tools/lib64/release/libdrcov.so"

${WORKDIR}/test_program &
PID=$(pgrep -f test_program)
CMD="$DRRUN -attach $PID -c $CLIENT -dump_text -logdir ${WORKDIR}/dump/"
$CMD
