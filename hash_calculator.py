#!/usr/bin/env python3

import hashlib
import argparse
import requests


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate the hash of a file.")
    parser.add_argument("--file", help="The file to calculate the hash of.")
    parser.add_argument("--api-key", help="The VirusTotal API key.")
    args = parser.parse_args()

    file_path = args.file
    api_key = args.api_key
    file_hash = calculate_file_hash(file_path)

    print(f"Hash of the file: {file_hash}")

    if "File cannot found!" not in file_hash and "An error occurred" not in file_hash:
        response = check_virustotal(file_hash, api_key)
        print(response)
    else:
        print(file_hash)
