# DBICodeCovBench
Benchmark using Docker to compare DBI Code Coverage generation

Heavily inspired by [ProFuzzBench](https://github.com/profuzzbench/profuzzbench)

Currently only [Frida](https://frida.re/), [DynamoRIO](https://dynamorio.org/) and [Intel Pin](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html) are available.

## Step-0. Set up environmental variables
```
git clone https://github.com/pasok0n/DBICodeCovBench.git
cd DBICodeCovBench
export DBIBENCH=$(pwd)
export PATH=$PATH:$DBIBENCH/scripts/
```

## Step-1. Build a docker image
The following commands create a docker image tagged dcmtk. The image should have everything available for fuzzing and code coverage collection.

```bash
cd $DBIBENCH
cd subjects/DICOM/dcmtk
docker build . -t dcmtk
```

## Step-2. Run instrumentation and fuzzing
Run [bb_docker.sh script](scripts/bb_docker.sh) to start an experiment. The script takes 6 arguments as listed below.

- ***1st argument (DOCIMAGE)*** : name of the docker image
- ***2nd argument (RUNS)***     : number of runs, one isolated Docker container is spawned for each run
- ***3rd argument (SAVETO)***   : path to a folder keeping the results
- ***4th argument (DBI)***      : DBI tool name (e.g., dynamorio)
- ***5th argument (OPTIONS)***  : either inject or spawn
- ***6th argument (OUTDIR)***   : name of the output folder created inside the docker container
- ***7th argument (TIMEOUT)***  : time for fuzzing in seconds

The following commands run 4 instances of DynamoRIO in spawn mode and 4 instances of PIN in attach mode to simultaenously instrument and fuzz (using boofuzz) Dcmtk in 60 seconds.

```bash
cd $PFBENCH
mkdir results-dcmtk

bb_docker.sh dcmtk 4 results-dcmtk dynamorio spawn out-dcmtk-dynamo 60 &
bb_docker.sh dcmtk 4 results-dcmtk pin attach out-dcmtk-pin 60
```

If the script runs successfully, its output should look similar to the text below.

```
DYNAMORIO: Instrumentation and fuzzing in progress ...
DYNAMORIO: Waiting for the following containers to stop:  f2da4b72b002 b7421386b288 cebbbc741f93 5c54104ddb86
DYNAMORIO: Collecting results and save them to results-dcmtk
DYNAMORIO: Collecting results from container f2da4b72b002
DYNAMORIO: Collecting results from container b7421386b288
DYNAMORIO: Collecting results from container cebbbc741f93
DYNAMORIO: Collecting results from container 5c54104ddb86
DYNAMORIO: I am done!
```

## Step-3. Comparing results

The results should be in 'results-dcmtk', where you can then compare the output of the DBI tools used in the run.