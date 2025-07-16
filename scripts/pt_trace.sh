#!/bin/bash

# if ptrace_scope is not set to 0, then set to 0 else set to 1
if [ $(cat /proc/sys/kernel/yama/ptrace_scope) -eq 0 ]; then
    echo "ptrace_scope is already set to 0"
    echo "Setting ptrace_scope to 1"
    echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
    exit 0
fi
echo "Setting ptrace_scope to 0"
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
exit 0