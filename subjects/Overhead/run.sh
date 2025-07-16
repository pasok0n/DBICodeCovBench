#!/bin/bash

echo 0 | tee /proc/sys/kernel/yama/ptrace_scope

cd $WORKDIR
python benchmark.py