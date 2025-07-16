#!/bin/bash

DOCIMAGE=$1   #name of the docker image
RUNS=$2       #number of runs
SAVETO=$3     #path to folder keeping the results

DBITOOL=$4   #DBITOOL name (e.g., pin) -- this name must match the name of the DBITOOL folder inside the Docker container
OPTIONS=$5    #spawn or attach
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
  id=$(docker run --cap-add=SYS_PTRACE --security-opt seccomp:unconfined --security-opt apparmor:unconfined --cpus=1 -d -it "$DOCIMAGE" /bin/bash -c "cd ${WORKDIR} && ./run.sh ${DBITOOL} ${OPTIONS} ${OUTDIR} ${TIMEOUT}")
  cids+=("${id::12}") #store only the first 12 characters of a container ID
done

dlist="" #docker list
for id in "${cids[@]}"; do
  dlist+=" ${id}"
done

#wait until all these dockers are stopped
printf "\n%s: Fuzzing in progress ...\n" "${DBITOOL^^}"
printf "%s: Waiting for the following containers to stop: %s\n" "${DBITOOL^^}" "${dlist}"
docker wait ${dlist} > /dev/null
wait

#collect the fuzzing results from the containers
printf "\n%s: Collecting results and save them to %s\n" "${DBITOOL^^}" "${SAVETO}"
index=1
for id in "${cids[@]}"; do
  printf "%s: Collecting results from container %s\n" "${DBITOOL^^}" "${id}"
  docker cp "${id}:/tmp" "${SAVETO}/${OUTDIR}_${index}" > /dev/null
  if [ -n "$DELETE" ]; then
    printf "Deleting %s\n" "${id}"
    docker rm "${id}" # Remove container now that we don't need it
  fi
  index=$((index+1))
done

printf "\n%s: I am done!\n" "${DBITOOL^^}"