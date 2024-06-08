# Hash Calculator, VirusTotal Checker and IP Info Fetcher

This Python application calculates the SHA-256 hash of a given file, queries this hash on the VirusTotal API to check if the file is malicious, and fetches information about a given IP address from the ipinfo.io service.

## Requirements

- Python 3.x
- `requests` library
- `hashlib` library
- `argparse` library

## Installation

1. Install the required library:

   Install the `requests` library by running:
   ```sh
   pip install requests
2. Make the script executable
   ```sh
   chmod +x hash_calculator.py
   
4. Move the script to /usr/local/bin for global access

   ```sh
   sudo mv hash_calculator.py /usr/local/bin/hashcalculator

6. Make the script executable in /usr/local/bin

   ```sh
   sudo chmod +x /usr/local/bin/hashcalculator

## Usage

hashcalculator --file <file_path> --apikey <virustotal_api_key>

## Command Line Arguments

* --file: Path to the file to calculate the hash.
* --apikey: VirusTotal API key.
* --ip: IP address.
* --ipinfo-token: IP info token.


## Example

* hashcalculator --file /home/user/example.txt --apikey your_virus_total_token
* hashcalculator --ip 8.8.8.8 --ipinfo-token your_ipinfo_token
