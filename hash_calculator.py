#!/usr/bin/env python3

import hashlib
import argparse
import requests
import json


def calculate_file_hash(file):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return "File cannot found!"
    except Exception as e:
        return f"An error occurred: {e}"


def check_virustotal(hash_value, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": api_key,
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return f"An error occurred: {response.text}"


def get_ip_info(ip_address, token):
    url = f"https://ipinfo.io/{ip_address}/json"
    headers = {
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return f"An error occurred: {response.text}"


def print_json_pretty(json_data):
    print(json.dumps(json_data, indent=4, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File hash calculator, VirusTotal checker, and IP info fetcher")
    parser.add_argument('--file', type=str, help="Path to the file to calculate the hash")
    parser.add_argument('--apikey', type=str, help="VirusTotal API key")
    parser.add_argument('--ip', type=str, help="IP address to fetch information")
    parser.add_argument('--ipinfo-token', type=str, help="Token for ipinfo.io API")
    args = parser.parse_args()

    if args.file and args.apikey:
        file_path = args.file
        api_key = args.apikey
        file_hash = calculate_file_hash(file_path)

        print(f"File: {file_path}")
        print(f"SHA-256 Hash: {file_hash}")

        if "File not found!" not in file_hash and "An error occurred:" not in file_hash:
            vt_result = check_virustotal(file_hash, api_key)
            print("VirusTotal Results:")
            print_json_pretty(vt_result)
        else:
            print(file_hash)
    elif args.ip and args.ipinfo_token:
        ip_info = get_ip_info(args.ip, args.ipinfo_token)
        print(f"IP Info for {args.ip}:")
        print_json_pretty(ip_info)
    else:
        print("Please provide either --file and --apikey for hash calculation "
              "and VirusTotal check, or --ip and --ipinfo-token for IP info.")
