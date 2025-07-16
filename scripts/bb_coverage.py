import os
import re
import statistics
from pathlib import Path

def extract_bb_count_dynamorio(file_path):
    """Extract BB count from DynamoRIO log file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            match = re.search(r'BB Table: (\d+) bbs', content)
            if match:
                return int(match.group(1))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return None

def extract_bb_count_frida(file_path):
    """Extract BB count from Frida log file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            match = re.search(r'BB Table: (\d+) bbs', content)
            if match:
                return int(match.group(1))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return None

def extract_bb_count_pin(file_path):
    """Extract BB count from Pin coverage file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            match = re.search(r'Total covered basic blocks: (\d+)', content)
            if match:
                return int(match.group(1))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return None

def calculate_stats(values):
    """Calculate average, min, max from a list of values"""
    if not values:
        return "-", "-", "-"
    
    avg = statistics.mean(values)
    min_val = min(values)
    max_val = max(values)
    
    return f"{avg:.2f}", str(min_val), str(max_val)

def process_application_tool_mode(base_path, app, tool, mode):
    """Process a specific application-tool-mode combination"""
    values = []
    total_expected = 4  # assuming 1-4 runs
    found_count = 0
    
    for i in range(1, total_expected + 1):
        subdir_name = f"{app}-{tool}-{mode}_{i}"
        subdir_path = base_path / subdir_name
        
        if not subdir_path.exists() or not subdir_path.is_dir():
            continue
        
        bb_count = None
        
        if tool == 'dynamorio':
            # Look for .log files
            log_files = list(subdir_path.glob('*.log'))
            if log_files:
                bb_count = extract_bb_count_dynamorio(log_files[0])
        elif tool == 'frida':
            if mode == 'attach':
                log_file = subdir_path / 'frida_inject.log'
            else:  # spawn
                log_file = subdir_path / 'frida-spawn.log'
            
            if log_file.exists():
                bb_count = extract_bb_count_frida(log_file)
        elif tool == 'pin':
            if mode == 'attach':
                log_file = subdir_path / 'pin_coverage_inject.log'
            else:  # spawn
                log_file = subdir_path / 'pin_coverage_spawn.log'
            
            if log_file.exists():
                bb_count = extract_bb_count_pin(log_file)
        
        if bb_count is not None:
            values.append(bb_count)
            found_count += 1
    
    return values, found_count, total_expected

def get_applications_from_folder(base_path):
    """Extract unique application names from folder structure"""
    base_path = Path(base_path)
    apps = set()
    
    # Get all subdirectories
    subdirs = [d for d in base_path.iterdir() if d.is_dir()]
    
    for subdir in subdirs:
        name = subdir.name
        
        # Parse directory name: app-tool-mode_number
        match = re.match(r'(.+)-(dynamorio|pin|frida)-(attach|spawn)_(\d+)', name)
        if match:
            app, tool, mode, number = match.groups()
            apps.add(app)
    
    return sorted(apps)

def process_folder(base_path):
    """Process all subfolders and extract BB counts"""
    base_path = Path(base_path)
    
    if not base_path.exists():
        raise FileNotFoundError(f"Path '{base_path}' does not exist.")
    
    # Get all applications
    applications = get_applications_from_folder(base_path)
    
    if not applications:
        print("No valid application folders found.")
        return {}
    
    # Dictionary to store results for each application
    results = {}
    
    tools = ['dynamorio', 'pin', 'frida']
    modes = ['attach', 'spawn']
    
    # Process each application
    for app in applications:
        print(f"Processing {app}...")
        results[app] = {}
        
        # Process each tool and mode combination
        for tool in tools:
            for mode in modes:
                values, found_count, total_expected = process_application_tool_mode(
                    base_path, app, tool, mode
                )
                
                # Calculate statistics
                avg, min_val, max_val = calculate_stats(values)
                count_str = f"({found_count}/{total_expected})" if found_count < total_expected else ""
                
                key = f"{tool}_{mode}"
                if found_count == 0:
                    results[app][key] = f"- {count_str}"
                else:
                    results[app][key] = f"average: {avg}, min: {min_val}, max: {max_val} {count_str}"
    
    return results

def save_results(results, output_file):
    """Save results to a file"""
    with open(output_file, 'w') as f:
        for app in sorted(results.keys()):
            f.write(f"{app}:\n")
            
            tools_modes = [
                ('dynamorio', 'attach'),
                ('dynamorio', 'spawn'),
                ('frida', 'attach'),
                ('frida', 'spawn'),
                ('pin', 'attach'),
                ('pin', 'spawn')
            ]
            
            for tool, mode in tools_modes:
                key = f"{tool}_{mode}"
                if key in results[app]:
                    f.write(f"  {tool} {mode}: {results[app][key]}\n")
                else:
                    f.write(f"  {tool} {mode}: -\n")
            
            f.write("\n")

def main():
    # Get folder path from user
    folder_path = input("Enter the path to the folder: ").strip()
    
    try:
        # Process the folder
        results = process_folder(folder_path)
        
        if not results:
            print("No results found. Please check the folder structure and file names.")
            return
        
        # Save results
        output_file = "bb_analysis_results.txt"
        save_results(results, output_file)
        
        print(f"\nResults saved to {output_file}")
        
        # Also print to console
        print("\nResults:")
        with open(output_file, 'r') as f:
            print(f.read())
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()