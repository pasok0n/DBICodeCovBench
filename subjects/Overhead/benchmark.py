import subprocess
import time
import re
import statistics
import os
import signal
from typing import List, Dict, Tuple

class PerformanceBenchmark:
    def __init__(self, program_name: str = "test_program"):
        self.program_name = program_name
        self.iterations = 100
        self.perf_events = ["cycles", "instructions", "cache-misses", "cache-references"]
        
        # Commands to test
        self.commands = {
            "baseline": f"./{program_name}",
            "dynamorio": "/home/ubuntu/dynamorio/bin64/drrun -attach {pid} -c /home/ubuntu/dynamorio/tools/lib64/release/libdrcov.so",
            "pin": "/home/ubuntu/pin/pin -pid {pid} -t /home/ubuntu/pin/source/tools/MyPinTool/obj-intel64/pin_cov.so",
            "frida": "python frida-drcov.py {pid}"
        }
        
        self.results = {}
        
    def start_test_program(self) -> subprocess.Popen:
        """Start the test program and return the process object"""
        try:
            process = subprocess.Popen(
                [f"./{self.program_name}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            # Give the program a moment to start
            time.sleep(0.1)
            return process
        except Exception as e:
            print(f"Error starting test program: {e}")
            return None
    
    def run_timing_test(self, command: str, name: str) -> List[float]:
        """Run timing tests for a command"""
        times = []
        print(f"Running timing tests for {name}...")
        
        for i in range(self.iterations):
            if i % 10 == 0:
                print(f"  Progress: {i}/{self.iterations}")
            
            if name == "baseline":
                # Run baseline test normally
                start_time = time.time()
                try:
                    result = subprocess.run(
                        command.split(), 
                        capture_output=True, 
                        text=True, 
                        timeout=10
                    )
                    end_time = time.time()
                    
                    if result.returncode == 0:
                        times.append(end_time - start_time)
                    else:
                        print(f"Warning: Command failed on iteration {i}")
                        
                except subprocess.TimeoutExpired:
                    print(f"Warning: Command timed out on iteration {i}")
                except Exception as e:
                    print(f"Error on iteration {i}: {e}")
            else:
                # Run attachment test
                try:
                    # Start the test program
                    test_process = self.start_test_program()
                    if test_process is None:
                        continue
                    
                    pid = test_process.pid
                    attach_command = command.format(pid=pid)
                    
                    start_time = time.time()
                    
                    # Start the tool attachment
                    tool_process = subprocess.Popen(
                        attach_command.split(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # Wait for both processes to complete
                    test_process.wait(timeout=10)
                    tool_process.wait(timeout=10)
                    
                    end_time = time.time()
                    
                    if test_process.returncode == 0:
                        times.append(end_time - start_time)
                    else:
                        print(f"Warning: Test program failed on iteration {i}")
                    
                    # Clean up processes
                    try:
                        if test_process.poll() is None:
                            test_process.terminate()
                        if tool_process.poll() is None:
                            tool_process.terminate()
                    except:
                        pass
                        
                except subprocess.TimeoutExpired:
                    print(f"Warning: Command timed out on iteration {i}")
                    try:
                        if test_process.poll() is None:
                            test_process.terminate()
                        if tool_process.poll() is None:
                            tool_process.terminate()
                    except:
                        pass
                except Exception as e:
                    print(f"Error on iteration {i}: {e}")
                    try:
                        if test_process.poll() is None:
                            test_process.terminate()
                        if tool_process.poll() is None:
                            tool_process.terminate()
                    except:
                        pass
                
        return times
    
    def run_perf_test(self, command: str, name: str) -> Dict[str, List[float]]:
        """Run perf stat tests for a command"""
        perf_data = {event: [] for event in self.perf_events}
        print(f"Running perf tests for {name}...")
        
        for i in range(self.iterations):
            if i % 10 == 0:
                print(f"  Progress: {i}/{self.iterations}")
            
            events_str = ",".join(self.perf_events)
            
            if name == "baseline":
                # Run baseline perf test normally
                perf_command = f"perf stat -e {events_str} {command}"
                
                try:
                    result = subprocess.run(
                        perf_command.split(),
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0:
                        stderr_output = result.stderr
                        parsed_data = self.parse_perf_output(stderr_output)
                        
                        for event in self.perf_events:
                            if event in parsed_data:
                                perf_data[event].append(parsed_data[event])
                    else:
                        print(f"Warning: Perf command failed on iteration {i}")
                        
                except subprocess.TimeoutExpired:
                    print(f"Warning: Perf command timed out on iteration {i}")
                except Exception as e:
                    print(f"Error on iteration {i}: {e}")
            else:
                # Run attachment perf test
                try:
                    # Start the test program
                    test_process = self.start_test_program()
                    if test_process is None:
                        continue
                    
                    pid = test_process.pid
                    attach_command = command.format(pid=pid)
                    
                    # Run perf on the test program process
                    perf_command = f"perf stat -e {events_str} -p {pid}"
                    
                    # Start perf monitoring
                    perf_process = subprocess.Popen(
                        perf_command.split(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # Start the tool attachment
                    tool_process = subprocess.Popen(
                        attach_command.split(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # Wait for test program to complete
                    test_process.wait(timeout=10)
                    
                    # Stop perf monitoring
                    perf_process.send_signal(signal.SIGINT)
                    perf_result = perf_process.communicate(timeout=10)
                    
                    # Wait for tool to complete
                    tool_process.wait(timeout=10)
                    
                    if test_process.returncode == 0:
                        stderr_output = perf_result[1]
                        parsed_data = self.parse_perf_output(stderr_output)
                        
                        for event in self.perf_events:
                            if event in parsed_data:
                                perf_data[event].append(parsed_data[event])
                    else:
                        print(f"Warning: Test program failed on iteration {i}")
                    
                    # Clean up processes
                    try:
                        if test_process.poll() is None:
                            test_process.terminate()
                        if tool_process.poll() is None:
                            tool_process.terminate()
                        if perf_process.poll() is None:
                            perf_process.terminate()
                    except:
                        pass
                        
                except subprocess.TimeoutExpired:
                    print(f"Warning: Perf command timed out on iteration {i}")
                    try:
                        if test_process.poll() is None:
                            test_process.terminate()
                        if tool_process.poll() is None:
                            tool_process.terminate()
                        if perf_process.poll() is None:
                            perf_process.terminate()
                    except:
                        pass
                except Exception as e:
                    print(f"Error on iteration {i}: {e}")
                    try:
                        if test_process.poll() is None:
                            test_process.terminate()
                        if tool_process.poll() is None:
                            tool_process.terminate()
                        if perf_process.poll() is None:
                            perf_process.terminate()
                    except:
                        pass
                
        return perf_data
    
    def parse_perf_output(self, output: str) -> Dict[str, float]:
        """Parse perf stat output to extract event values"""
        parsed = {}
        
        for line in output.split('\n'):
            for event in self.perf_events:
                if event in line:
                    # Extract number from perf output
                    numbers = re.findall(r'([\d,]+)', line)
                    if numbers:
                        # Remove commas and convert to float
                        value = float(numbers[0].replace(',', ''))
                        parsed[event] = value
                        break
                        
        return parsed
    
    def calculate_stats(self, data: List[float]) -> Dict[str, float]:
        """Calculate statistical measures"""
        if not data:
            return {"mean": 0, "median": 0, "std_dev": 0, "min": 0, "max": 0}
            
        return {
            "mean": statistics.mean(data),
            "median": statistics.median(data),
            "std_dev": statistics.stdev(data) if len(data) > 1 else 0,
            "min": min(data),
            "max": max(data)
        }
    
    def calculate_overhead(self, baseline_stats: Dict[str, float], 
                         tool_stats: Dict[str, float]) -> float:
        """Calculate overhead percentage"""
        if baseline_stats["mean"] == 0:
            return 0
        return ((tool_stats["mean"] - baseline_stats["mean"]) / baseline_stats["mean"]) * 100
    
    def save_raw_data(self, data: List[float], filename: str):
        """Save raw measurement data to file"""
        with open(filename, 'w') as f:
            f.write("Measurement,Value\n")
            for i, value in enumerate(data, 1):
                f.write(f"{i},{value}\n")
    
    def save_perf_data(self, data: Dict[str, List[float]], filename: str):
        """Save perf measurement data to file"""
        with open(filename, 'w') as f:
            # Write header
            f.write("Measurement," + ",".join(self.perf_events) + "\n")
            
            # Find maximum length
            max_len = max(len(values) for values in data.values()) if data else 0
            
            # Write data rows
            for i in range(max_len):
                row = [str(i + 1)]
                for event in self.perf_events:
                    if i < len(data[event]):
                        row.append(str(data[event][i]))
                    else:
                        row.append("")
                f.write(",".join(row) + "\n")
    
    def run_all_tests(self):
        """Run all performance tests"""
        print("Starting performance benchmark...")
        
        # Test order: baseline first, then attachment tests
        test_order = ["baseline", "dynamorio", "pin", "frida"]
        
        for name in test_order:
            if name not in self.commands:
                continue
                
            command = self.commands[name]
            print(f"\n{'='*50}")
            print(f"Testing: {name}")
            if name == "baseline":
                print(f"Command: {command}")
            else:
                print(f"Attachment command: {command}")
            print(f"{'='*50}")
            
            # Run timing tests
            timing_data = self.run_timing_test(command, name)
            
            # Run perf tests
            perf_data = self.run_perf_test(command, name)
            
            # Store results
            self.results[name] = {
                "timing": timing_data,
                "perf": perf_data
            }
            
            # Save raw data
            self.save_raw_data(timing_data, f"{name}_timing_data.csv")
            self.save_perf_data(perf_data, f"{name}_perf_data.csv")
    
    def generate_report(self):
        """Generate final performance report"""
        print("\nGenerating performance report...")
        
        with open("performance_report.txt", 'w') as f:
            f.write("PERFORMANCE BENCHMARK REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write("Testing methodology: Baseline run standalone, tools attached to running processes\n\n")
            
            # Timing results
            f.write("TIMING RESULTS (seconds)\n")
            f.write("-" * 30 + "\n")
            
            timing_stats = {}
            for name, data in self.results.items():
                stats = self.calculate_stats(data["timing"])
                timing_stats[name] = stats
                
                f.write(f"\n{name.upper()}:\n")
                f.write(f"  Mean: {stats['mean']:.6f}s\n")
                f.write(f"  Median: {stats['median']:.6f}s\n")
                f.write(f"  Std Dev: {stats['std_dev']:.6f}s\n")
                f.write(f"  Min: {stats['min']:.6f}s\n")
                f.write(f"  Max: {stats['max']:.6f}s\n")
                f.write(f"  Samples: {len(data['timing'])}\n")
            
            # Timing overhead calculations
            f.write("\nTIMING OVERHEAD ANALYSIS\n")
            f.write("-" * 30 + "\n")
            
            baseline_timing = timing_stats["baseline"]
            for name, stats in timing_stats.items():
                if name != "baseline":
                    overhead = self.calculate_overhead(baseline_timing, stats)
                    overhead_seconds = stats["mean"] - baseline_timing["mean"]
                    f.write(f"{name.upper()} vs BASELINE:\n")
                    f.write(f"  Overhead: {overhead:.2f}%\n")
                    f.write(f"  Overhead: {overhead_seconds:.6f}s\n\n")
            
            # Performance counter results
            f.write("PERFORMANCE COUNTER RESULTS\n")
            f.write("-" * 35 + "\n")
            
            perf_stats = {}
            for name, data in self.results.items():
                perf_stats[name] = {}
                f.write(f"\n{name.upper()}:\n")
                
                for event in self.perf_events:
                    if event in data["perf"] and data["perf"][event]:
                        stats = self.calculate_stats(data["perf"][event])
                        perf_stats[name][event] = stats
                        
                        f.write(f"  {event}:\n")
                        f.write(f"    Mean: {stats['mean']:.0f}\n")
                        f.write(f"    Median: {stats['median']:.0f}\n")
                        f.write(f"    Std Dev: {stats['std_dev']:.0f}\n")
                        f.write(f"    Samples: {len(data['perf'][event])}\n")
            
            # Performance counter overhead
            f.write("\nPERFORMANCE COUNTER OVERHEAD ANALYSIS\n")
            f.write("-" * 40 + "\n")
            
            if "baseline" in perf_stats:
                baseline_perf = perf_stats["baseline"]
                
                for name, stats in perf_stats.items():
                    if name != "baseline":
                        f.write(f"\n{name.upper()} vs BASELINE:\n")
                        
                        for event in self.perf_events:
                            if event in baseline_perf and event in stats:
                                overhead = self.calculate_overhead(
                                    baseline_perf[event], 
                                    stats[event]
                                )
                                f.write(f"  {event} overhead: {overhead:.2f}%\n")
            
            f.write(f"\nTotal iterations per test: {self.iterations}\n")
            f.write(f"Test completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        print("Report saved to performance_report.txt")
        print("Raw data saved to individual CSV files")

def main():
    # Check if test_program exists
    if not os.path.exists("test_program"):
        print("Error: test_program not found. Please compile it first.")
        return
    
    benchmark = PerformanceBenchmark()
    benchmark.run_all_tests()
    benchmark.generate_report()
    
    print("\nBenchmark completed successfully!")
    print("Files generated:")
    print("- performance_report.txt (summary)")
    print("- baseline_timing_data.csv")
    print("- baseline_perf_data.csv")
    print("- dynamorio_timing_data.csv")
    print("- dynamorio_perf_data.csv")
    print("- pin_timing_data.csv")
    print("- pin_perf_data.csv")
    print("- frida_timing_data.csv")
    print("- frida_perf_data.csv")

if __name__ == "__main__":
    main()