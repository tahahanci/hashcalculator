#!/usr/bin/env python3

import hashlib
import argparse


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate the hash of a file.")
    parser.add_argument("--file", help="The file to calculate the hash of.")
    args = parser.parse_args()
    file_path = args.file
    print(calculate_file_hash(file_path))
