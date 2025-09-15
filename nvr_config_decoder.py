#!/usr/bin/env python3
"""
NVR Config Decoder
Decodes compressed configuration files with NVHR header format
"""

import sys
import zlib
import argparse
from pathlib import Path

def decode_nvr_config(input_file, output_file=None):
    """
    Decode NVR configuration file with NVHR header

    Args:
        input_file: Path to the input .bak file
        output_file: Optional output file path

    Returns:
        Decoded configuration as string
    """
    try:
        # Read the binary file
        with open(input_file, 'rb') as f:
            data = f.read()

        print(f"File size: {len(data)} bytes")

        # Check for NVHR header
        if not data.startswith(b'NVHR'):
            print("Warning: File doesn't start with NVHR header")

        # Display header info
        header = data[:20]
        print(f"Header: {header}")

        # Try decompression from offset 0x14 (20 bytes)
        compressed_data = data[0x14:]

        try:
            decompressed = zlib.decompress(compressed_data)
            print(f"SUCCESS - Decompressed {len(decompressed)} bytes")

            # Decode to text
            config_text = decompressed.decode('utf-8', errors='ignore')

            # Save to output file if specified
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(config_text)
                print(f"Saved to: {output_file}")

            return config_text

        except zlib.error as e:
            print(f"Zlib decompression failed: {e}")
            print("Trying alternative offsets...")

            # Try other common offsets
            for offset in [0x10, 0x18, 0x20, 0x24]:
                try:
                    compressed_data = data[offset:]
                    decompressed = zlib.decompress(compressed_data)
                    print(f"SUCCESS at offset {hex(offset)} - Decompressed {len(decompressed)} bytes")

                    config_text = decompressed.decode('utf-8', errors='ignore')

                    if output_file:
                        with open(output_file, 'w', encoding='utf-8') as f:
                            f.write(config_text)
                        print(f"Saved to: {output_file}")

                    return config_text

                except zlib.error:
                    continue

            print("Failed to decompress with any known offset")
            return None

    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def analyze_config(config_text):
    """
    Analyze the decoded configuration for security issues
    """
    if not config_text:
        return

    print("\n=== SECURITY ANALYSIS ===")

    lines = config_text.split('\n')
    suspicious_items = []

    for i, line in enumerate(lines, 1):
        line = line.strip()

        # Look for credentials
        if 'password(' in line.lower():
            suspicious_items.append(f"Line {i}: Password found - {line}")

        # Look for usernames
        if 'username(' in line.lower():
            suspicious_items.append(f"Line {i}: Username found - {line}")

        # Look for command injection
        if 'curl' in line or 'wget' in line or 'sh' in line:
            suspicious_items.append(f"Line {i}: Potential command injection - {line}")

        # Look for external IPs
        if 'http://' in line and not ('localhost' in line or '127.0.0.1' in line):
            suspicious_items.append(f"Line {i}: External URL - {line}")

    if suspicious_items:
        print("SECURITY CONCERNS FOUND:")
        for item in suspicious_items:
            print(f"  ⚠️  {item}")
    else:
        print("No obvious security concerns detected")

def main():
    parser = argparse.ArgumentParser(description='Decode NVR configuration files')
    parser.add_argument('input', help='Input .bak file to decode')
    parser.add_argument('-o', '--output', help='Output file for decoded config')
    parser.add_argument('-a', '--analyze', action='store_true',
                       help='Perform security analysis on decoded config')
    parser.add_argument('-p', '--preview', type=int, default=500,
                       help='Number of characters to preview (default: 500)')

    args = parser.parse_args()

    # Set default output filename
    if not args.output:
        input_path = Path(args.input)
        args.output = input_path.with_suffix('.txt')

    print(f"Decoding: {args.input}")
    print(f"Output: {args.output}")
    print("-" * 50)

    # Decode the configuration
    config_text = decode_nvr_config(args.input, args.output)

    if config_text:
        # Show preview
        print(f"\nFirst {args.preview} characters:")
        print("-" * 30)
        print(config_text[:args.preview])
        if len(config_text) > args.preview:
            print("...")

        # Perform security analysis if requested
        if args.analyze:
            analyze_config(config_text)
    else:
        print("Failed to decode configuration file")
        sys.exit(1)

if __name__ == '__main__':
    main()