# Hash Calculator and VirusTotal Checker

This Python application calculates the SHA-256 hash of a given file and queries this hash on the VirusTotal API to check if the file is malicious.

## Requirements

- Python 3.x
- `requests` library

## Installation

1. **Install the required library:**

   Install the `requests` library by running:
   ```sh
   pip install requests
2. **Make the script executable

   chmod +x hash_calculator.py
   
3. **Move the script to /usr/local/bin for global access

   sudo mv hash_calculator.py /usr/local/bin/hashcalculator

4. **Make the script executable in /usr/local/bin

   sudo chmod +x /usr/local/bin/hashcalculator

## Usage

hashcalculator --file <file_path> --apikey <virustotal_api_key>

## Command Line Arguments

* --file: Path to the file to calculate the hash.
* --apikey: VirusTotal API key.

## Example

hashcalculator --file /home/user/example.txt --apikey 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef   
