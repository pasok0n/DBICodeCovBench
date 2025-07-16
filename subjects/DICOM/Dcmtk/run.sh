#!/bin/bash

DBI=$1        #DBI name (e.g., pin) -- this name must match the name of the DBI folder inside the Docker container
OPTIONS=$2    #spawn or inject
OUTDIR=$3     #name of the output folder
TIMEOUT=$4    #time for fuzzing

strstr() {
  [ "${1#*$2*}" = "$1" ] && return 1
  return 0
}

echo 0 | tee /proc/sys/kernel/yama/ptrace_scope

if $(strstr $DBI "dynamorio") || $(strstr $DBI "pin") || $(strstr $DBI "frida"); then

  cd $WORKDIR
  mkdir ${OUTDIR}

  if $(strstr $DBI "dynamorio"); then
    if $(strstr $OPTIONS "attach"); then
      ${WORKDIR}/dcmtk/build/bin/dcmqrscp --single-process &
      PID=$(pgrep -f dcmqrscp)
      ./drcov_inject.sh ${OUTDIR} $PID &
      timeout -k 0 --preserve-status $TIMEOUT python dicom_fuzz.py
      pkill -f dcmqrscp
      sleep 10
    elif $(strstr $OPTIONS "spawn"); then
      timeout -k 0 --preserve-status $TIMEOUT ./drcov_spawn.sh ${OUTDIR} ${WORKDIR}/dcmtk/build/bin/dcmqrscp --single-process &
      timeout -k 0 --preserve-status $TIMEOUT python dicom_fuzz.py
    fi
  fi

  if $(strstr $DBI "pin"); then
    if $(strstr $OPTIONS "attach"); then
      ${WORKDIR}/dcmtk/build/bin/dcmqrscp --single-process &
      PID=$(pgrep -f dcmqrscp)
      ./run_pin.sh ${OUTDIR} -pid $PID &
      timeout -k 0 --preserve-status $TIMEOUT python dicom_fuzz.py
      pkill -f dcmqrscp
      sleep 10
    elif $(strstr $OPTIONS "spawn"); then # Pin takes a long time to instrument the target
      timeout -k 0 --preserve-status $(($TIMEOUT + 12)) ./run_pin.sh ${OUTDIR} -- ${WORKDIR}/dcmtk/build/bin/dcmqrscp --single-process &
      sleep 12
      timeout -k 0 --preserve-status $TIMEOUT python dicom_fuzz.py
      sleep 10
    fi
  fi

  if $(strstr $DBI "frida"); then
    if $(strstr $OPTIONS "attach"); then
      ${WORKDIR}/dcmtk/build/bin/dcmqrscp --single-process &
      PID=$(pgrep -f dcmqrscp)
      python frida-drcov.py -o ${OUTDIR}/frida_inject.log $PID &
      timeout -k 0 --preserve-status $TIMEOUT python dicom_fuzz.py
      pkill -f dcmqrscp
      sleep 10
    elif $(strstr $OPTIONS "spawn"); then
      timeout -k 0 --preserve-status $TIMEOUT python frida-spawn.py -o ${OUTDIR}/frida-spawn.log ${WORKDIR}/dcmtk/build/bin/dcmqrscp --single-process &
      timeout -k 0 --preserve-status $TIMEOUT python dicom_fuzz.py
      sleep 5
      #mv frida-spawn.log ${OUTDIR}/frida-spawn.log
    fi
  fi

  #Step-3. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  cd ${WORKDIR}/
  #sleep 5 #waiting for DBI Tools to save output
  #tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}


  exit $STATUS
fi