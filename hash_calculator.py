import hashlib
import sys


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
    if len(sys.argv) != 2:
        print("python script.py <file_path>")
    else:
        file_path = sys.argv[1]
        file_hash = calculate_file_hash(file_path)
        print(f"File: {file_path}")
        print(f"SHA-256 Hash: {file_hash}")
