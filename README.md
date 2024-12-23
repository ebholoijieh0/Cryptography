AES Encryption/Decryption Tool

This project provides a Python-based command-line tool for encrypting and decrypting files using multiple AES modes. 
Supported modes include ECB, CBC, CTR, GCM, and CCM. Key sizes can be 128, 192, 256, or a non-standard 512 (truncated to 256 bits for actual AES usage).
Features

    Modes:
        ECB (Electronic Codebook)
        CBC (Cipher Block Chaining)
        CTR (Counter)
        GCM (Galois/Counter Mode)
        CCM (Counter with CBC-MAC)

    Key Sizes:
        128, 192, 256 (standard AES sizes)
        512 bits (non-standard, truncated to 256 bits in practice)

    Padding:
        Automatic PKCS#7 padding for block modes (ECB/CBC).

    Correct IV/Nonce Sizes:
        CTR requires a 16-byte IV.
        GCM uses a 12-byte nonce.
        CCM uses a 7–13-byte nonce (set to 13 by default in this code).

    Automatic Output Filenames (if --output is not specified):
        For encryption, it will create a file like:
        encrypt_<mode>_<timestamp>.json
        For decryption, it will create a file like:
        decrypt_<mode>_<timestamp>.dec

    Optional Data Key:
        You can parse a separate data key file (base64-encoded) and XOR it with the derived key. (Not recommended in production; purely demonstrative.)

    No Logging to error.log:
        This code does not write to error.log; it prints errors to the console instead.

Installation

    Clone or download the project files:
        crypto_utils.py
        main.py
        (Optionally) a requirements.txt file

    Install dependencies:

pip install -r requirements.txt

The requirements.txt should contain:

cryptography
colorama

Or install them manually:

    pip install cryptography colorama

    Ensure you have Python 3.7+ installed.

How to Run

    Encryption example (default: AES-128 CBC):

python main.py encrypt \
    --password "mysupersecret" \
    --input plain.txt

    This will create a file named something like encrypt_cbc_20241223_153045.json in the current directory.

Decryption example:

python main.py decrypt \
    --password "mysupersecret" \
    --input encrypt_cbc_20241223_153045.json

    By default, it will produce a file named decrypt_cbc_20241223_153100.dec.

Specifying output manually:

python main.py encrypt \
    --password "mysupersecret" \
    --input plain.txt \
    --output secret.json \
    --aes-mode ctr \
    --key-size 256

    This encrypts plain.txt using AES-256 CTR and saves to secret.json.

Using a data key file:

python main.py encrypt \
    --password "mysupersecret" \
    --input secret_data.bin \
    --data-key-file data_key.bin \
    --aes-mode gcm \
    --key-size 192

    The tool parses data_key.bin (base64-encoded), XORs it with the derived key, and encrypts with AES-192 GCM.

Choosing AES-CCM:

python main.py encrypt \
    --password "mysupersecret" \
    --input data.bin \
    --aes-mode ccm \
    --key-size 256

    AES-CCM merges the tag into ciphertext and uses a 13-byte nonce by default.

Non-standard 512-bit derivation (truncated to 256 bits) + ECB:

    python main.py encrypt \
        --password "mysupersecret" \
        --input doc.pdf \
        --aes-mode ecb \
        --key-size 512

        Internally truncates to 256 bits for AES-ECB.

Command-Line Options

usage: main.py [-h] {encrypt,decrypt} --password PASSWORD --input INPUT
               [--output OUTPUT]
               [--salt-file SALT_FILE]
               [--data-key-file DATA_KEY_FILE]
               [--aes-mode AES_MODE]
               [--key-size KEY_SIZE]

AES tool supporting multiple modes and key sizes, with error fixes.

positional arguments:
  {encrypt,decrypt}     Mode: encrypt or decrypt

optional arguments:
  -h, --help            show this help message and exit
  --password PASSWORD, -p PASSWORD
                        Password to derive key
  --input INPUT, -i INPUT
                        Input file to encrypt/decrypt
  --output OUTPUT, -o OUTPUT
                        Output file to write result (auto-generated if omitted)
  --salt-file SALT_FILE, -s SALT_FILE
                        File to read/store salt (default: salt.bin)
  --data-key-file DATA_KEY_FILE, -d DATA_KEY_FILE
                        Base64-encoded data key file to XOR with derived key
  --aes-mode AES_MODE   AES mode (ecb, cbc, ctr, gcm, ccm). Default = cbc
  --key-size KEY_SIZE   AES key size in bits (128,192,256,512). Default = 128

Key notes:

    --aes-mode can be any of: ecb, cbc, ctr, gcm, ccm.
    --key-size can be 128, 192, 256, or 512 (non-standard, effectively 256).
    --salt-file indicates where the salt is stored or read from; if it doesn’t exist, it’s created.
    --data-key-file (optional) to XOR with your derived key.

Troubleshooting

    Block size error:
        ECB/CBC require PKCS#7 padding; this code handles it automatically.
    Invalid nonce size error:
        CTR must use a 16-byte IV, which is enforced here.
        GCM uses 12 bytes by default.
        CCM uses a 7–13 byte nonce (13 by default).

If you encounter other issues, make sure you have the latest cryptography library installed, and confirm you’re passing the correct arguments.
Security Notes

    ECB is generally not recommended for sensitive data.
    CBC + PKCS#7 is not authenticated; consider GCM or CCM for authenticated encryption.
    512-bit key derivation is not standard AES. The code truncates to 256 bits internally.
    XORing an additional data key is purely demonstrative, not a recommended cryptographic practice.

Use these modes and key-management patterns with caution in real-world scenarios, and always follow best practices from official cryptography resources.
