import argparse
import os
import json
from datetime import datetime

from colorama import init, Fore, Style

from crypto_utils import (
    log_error,           # Does nothing
    create_key_from_password,
    encrypt_data,
    decrypt_data,
    parse_data_key
)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def print_intro():
    """
    Print an intro banner with a skull to set the mood.
    """
    # Notice how we've escaped or replaced the extra `"""` to avoid breaking the string
    skull_art = """
           .... NO ESCAPE ....
                uuuuuuu
            uu$$$$$$$$$$$uu
         uu$$$$$$$$$$$$$$$$$uu
        u$$$$$$$$$$$$$$$$$$$$$u
        u$$$$$$$$$$$$$$$$$$$$$u
        u$$$$$$"   "$$$"   "$$$$$u
        "$$$$"      u$u       $$$$"
         $$$u       u$u       u$$$
         $$$u      u$$$u      u$$$
          "$$$$uu$$$   $$$uu$$$$"
           "$$$$$$$"   "$$$$$$$"
             u$$$$$$$u$$$$$$$u
              u$"$"$"$"$"$"$u
   uuu        $$u$ $ $ $ $u$$       uuu
  u$$$$        $$$$$u$u$u$$$       u$$$$
   $$$$$uu      "$$$$$$$$$"     uu$$$$$$
 u$$$$$$$$$$$uu    \"\"\"\"\"    uuuu$$$$$$$$$$
 $$$$\"\"\"$$$$$$$$$$uuu   uu$$$$$$$$$\"\"\"$$$\"
   \"\"\"      \"\"$$$$$$$$$$$uu \"\"$\"\"\"
            uuuu \"\"$$$$$$$$$$uuu
   u$$$uuu$$$$$$$$$uu \"\"$$$$$$$$$$$uuu$$$
   $$$$$$$$$$\"\"\"\"           \"\"$$$$$$$$$$$\"
    \"$$$$$\"                      \"\"$$$$\"\"
      $$$\"                         $$$$\"
    """
    
    print(Fore.RED + skull_art + Style.RESET_ALL)
    print(Fore.YELLOW + "Welcome to the AES Encryption/Decryption Tool" + Style.RESET_ALL)
    print(Fore.CYAN + "Supported modes: ECB, CBC, CTR, GCM, CCM" + Style.RESET_ALL)
    print(Fore.MAGENTA + "Supported key sizes: 128, 192, 256, 512 (512 => truncated to 256)" + Style.RESET_ALL)
    print(Fore.BLUE + "PKCS#7 padding applied for ECB/CBC. IV/nonce sizes set to fix errors." + Style.RESET_ALL)


def main():
    parser = argparse.ArgumentParser(description="AES tool supporting multiple modes and key sizes, with error fixes.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("--password", "-p", required=True, help="Password to derive key")
    parser.add_argument("--input", "-i", required=True, help="Input file to encrypt/decrypt")
    parser.add_argument("--output", "-o", help="Output file to write result (auto-generated if omitted)")
    parser.add_argument("--salt-file", "-s", default="salt.bin", help="File to read/store salt")
    parser.add_argument("--data-key-file", "-d", help="Optional base64-encoded data key to XOR with derived key")
    parser.add_argument("--aes-mode", default="cbc", help="AES mode (ecb, cbc, ctr, gcm, ccm). Default = cbc")
    parser.add_argument("--key-size", type=int, default=128, help="AES key size in bits (128,192,256,512)")

    args = parser.parse_args()

    # Print introduction
    print_intro()

    # 1. Load/generate salt
    try:
        if os.path.exists(args.salt_file):
            with open(args.salt_file, 'rb') as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(args.salt_file, 'wb') as f:
                f.write(salt)
    except Exception as e:
        print(Fore.RED + f"Error handling salt file: {e}" + Style.RESET_ALL)
        raise SystemExit(1)

    # 2. Create derived key from password (with requested key size)
    try:
        derived_key = create_key_from_password(args.password, salt, key_size=args.key_size)
    except Exception as e:
        print(Fore.RED + f"Could not create derived key: {e}" + Style.RESET_ALL)
        raise SystemExit(1)

    # 3. Optionally parse data key file and XOR
    if args.data_key_file:
        try:
            extra_key = parse_data_key(args.data_key_file)
            # XOR them for demonstration (not recommended in production)
            derived_key = bytes(a ^ b for (a, b) in zip(derived_key, extra_key[:len(derived_key)]))
        except Exception as e:
            print(Fore.RED + f"Could not parse or combine data key: {e}" + Style.RESET_ALL)
            raise SystemExit(1)

    # 4. Read input data
    try:
        with open(args.input, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(Fore.RED + f"Could not read input file: {e}" + Style.RESET_ALL)
        raise SystemExit(1)

    # If user doesn't provide an output file, generate one
    if not args.output:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        if args.mode == "encrypt":
            args.output = f"encrypt_{args.aes_mode}_{timestamp_str}.json"
        else:
            args.output = f"decrypt_{args.aes_mode}_{timestamp_str}.dec"

    # 5. Encrypt or decrypt
    if args.mode == "encrypt":
        try:
            result = encrypt_data(derived_key, data, aes_mode=args.aes_mode)
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(Fore.GREEN + f"File encrypted successfully: {args.output}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Encryption failed: {e}" + Style.RESET_ALL)
            raise SystemExit(1)
    else:  # decrypt
        try:
            with open(args.input, 'r') as f:
                data_dict = json.load(f)
            decrypted = decrypt_data(derived_key, data_dict)
            with open(args.output, 'wb') as f:
                f.write(decrypted)
            print(Fore.GREEN + f"File decrypted successfully: {args.output}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Decryption failed: {e}" + Style.RESET_ALL)
            raise SystemExit(1)


if __name__ == "__main__":
    main()