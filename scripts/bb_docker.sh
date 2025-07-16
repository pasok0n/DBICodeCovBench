#!/bin/bash

DOCIMAGE=$1   #name of the docker image
RUNS=$2       #number of runs
SAVETO=$3     #path to folder keeping the results

DBITOOL=$4   #DBITOOL name (e.g., pin) -- this name must match the name of the DBITOOL folder inside the Docker container
OPTIONS=$5    #spawn or inject
OUTDIR=$6     #name of the output folder created inside the docker container
TIMEOUT=$7    #time for fuzzing
DELETE=$8

WORKDIR="/home/ubuntu/experiments"

# Create the SAVETO directory if it does not exist
mkdir -p "$SAVETO"

#keep all container ids
cids=()

#create one container for each run
for i in $(seq 1 $RUNS); do
  id=$(docker run --cap-add=SYS_PTRACE --security-opt seccomp:unconfined --security-opt apparmor:unconfined --cpus=1 -d -it $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && ./run.sh ${DBITOOL} ${OPTIONS} ${OUTDIR} ${TIMEOUT}")
  cids+=(${id::12}) #store only the first 12 characters of a container ID
done

dlist="" #docker list
for id in ${cids[@]}; do
  dlist+=" ${id}"
done

#wait until all these dockers are stopped
printf "\n${DBITOOL^^}: Instrumentation and fuzzing in progress ..."
printf "\n${DBITOOL^^}: Waiting for the following containers to stop: ${dlist}"
docker wait ${dlist} > /dev/null
wait
sleep 2

#collect the fuzzing results from the containers
printf "\n${DBITOOL^^}: Collecting results and save them to ${SAVETO}"
index=1
for id in ${cids[@]}; do
  printf "\n${DBITOOL^^}: Collecting results from container ${id}"
  docker cp ${id}:/home/ubuntu/experiments/${OUTDIR} ${SAVETO}/${OUTDIR}_${index} > /dev/null
  if [ $? -ne 0 ]; then
    echo "Failed to copy from container ${id}"
  fi
  if [ ! -z $DELETE ]; then
    printf "\nDeleting ${id}"
    docker rm ${id} # Remove container now that we don't need it
  fi
  index=$((index+1))
done

printf "\n${DBITOOL^^}: I am done!\n"