import os
import sys
import struct
import argparse
from collections import Counter

MAP_SIZE = 65536  # AFL bitmap size in bytes

def read_bitmap(file_path):
    """Read the AFL-style bitmap from a binary file."""
    with open(file_path, 'rb') as f:
        data = f.read()
    if len(data) != MAP_SIZE:
        raise ValueError(f"Invalid bitmap size: {len(data)} bytes (expected {MAP_SIZE})")
    # Unpack as 65536 unsigned bytes
    bitmap = struct.unpack(f'<{MAP_SIZE}B', data)
    return bitmap

def analyze_bitmap(bitmap):
    """Analyze the bitmap and return coverage statistics."""
    unique_edges = sum(1 for count in bitmap if count > 0)
    total_hits = sum(bitmap)  # Approximate, as counts saturate at 255
    # Bucket distribution (AFL-style logarithmic buckets)
    buckets = Counter()
    for count in bitmap:
        if count == 0:
            continue
        elif count == 1:
            buckets['1'] += 1
        elif count == 2:
            buckets['2'] += 1
        elif 3 <= count <= 7:
            buckets['3-7'] += 1
        elif 8 <= count <= 15:
            buckets['8-15'] += 1
        elif 16 <= count <= 31:
            buckets['16-31'] += 1
        elif 32 <= count <= 127:
            buckets['32-127'] += 1
        else:  # 128-255
            buckets['128+'] += 1
    return {
        'unique_edges': unique_edges,
        'coverage_percentage': (unique_edges / MAP_SIZE) * 100,
        'total_hits': total_hits,
        'bucket_distribution': dict(buckets)
    }

def main():
    parser = argparse.ArgumentParser(description="Analyze AFL-style coverage bitmaps.")
    parser.add_argument('input', help="Path to a single .bin file or a directory containing .bin files")
    args = parser.parse_args()

    if os.path.isdir(args.input):
        files = [os.path.join(args.input, f) for f in os.listdir(args.input) if f.endswith('.bin')]
    else:
        files = [args.input]

    for file_path in files:
        try:
            bitmap = read_bitmap(file_path)
            stats = analyze_bitmap(bitmap)
            print(f"Analysis for {file_path}:")
            print(f"  Unique edges hit: {stats['unique_edges']} ({stats['coverage_percentage']:.2f}%)")
            print(f"  Total hits (approx.): {stats['total_hits']}")
            print("  Bucket distribution:")
            for bucket, count in stats['bucket_distribution'].items():
                print(f"    {bucket}: {count}")
            print()
        except Exception as e:
            print(f"Error processing {file_path}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()