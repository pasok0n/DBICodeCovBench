### Overhead

To messure the overhead (time,cycles, instructions, cache-misses, cache-references) run:
```bash
mkdir results
docker build . -t overhead
./run_benchmark.sh overhead results
```
and wait for a couple min, the results will be saved in the results folder.