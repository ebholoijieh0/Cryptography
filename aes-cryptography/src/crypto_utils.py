import os
import base64

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


def log_error(_message: str):
    """
    Dummy function that does nothing, leaving error.log empty.
    """
    pass


def create_key_from_password(
    password: str,
    salt: bytes,
    key_size: int = 128,
    iterations: int = 100_000
) -> bytes:
    """
    Derive a key of specified bit length from a given password and salt.
    Supported key sizes for AES: 128, 192, 256 bits. 
    We allow 512 bits, but that is not part of AES standard;
    if 512 is requested, we truncate to 256 bits internally.

    PBKDF2 with HMAC-SHA256 is used as the KDF.

    :param password: user password
    :param salt: random salt
    :param key_size: 128, 192, 256, or 512 bits
    :param iterations: PBKDF2 iteration count
    :return: derived key (bytes)
    """
    if key_size not in (128, 192, 256, 512):
        raise ValueError(f"Unsupported key size: {key_size}. Use 128, 192, 256, or 512.")

    # PBKDF2 length in bytes
    length_in_bytes = key_size // 8

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length_in_bytes,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    full_key = kdf.derive(password.encode('utf-8'))

    # If 512 bits is requested, truncate to 256 bits (32 bytes) for real AES
    if key_size == 512:
        return full_key[:32]

    return full_key


def _pkcs7_pad(data: bytes, block_size_bits: int = 128) -> bytes:
    """
    Apply PKCS#7 padding to data for block cipher modes (ECB, CBC).
    AES block size is always 128 bits.
    """
    padder = padding.PKCS7(block_size_bits).padder()
    return padder.update(data) + padder.finalize()


def _pkcs7_unpad(data: bytes, block_size_bits: int = 128) -> bytes:
    """
    Remove PKCS#7 padding from data for block cipher modes.
    """
    unpadder = padding.PKCS7(block_size_bits).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def parse_data_key(file_path: str) -> bytes:
    """
    Parse a base64-encoded data key from a file.
    """
    try:
        with open(file_path, 'rb') as f:
            encoded_key = f.read().strip()
        return base64.b64decode(encoded_key)
    except Exception:
        # We do not log anything to error.log
        raise


def encrypt_data(key: bytes, plaintext: bytes, aes_mode: str = 'cbc') -> dict:
    """
    Encrypt 'plaintext' using AES in 'aes_mode'.
    Supports: ECB, CBC, CTR, GCM, CCM.

    Returns a dict with fields:
      - 'mode': the AES mode
      - 'ciphertext': base64-encoded ciphertext
      - 'iv' or 'nonce' (if relevant)
      - 'tag' if GCM
      - CCM merges tag into ciphertext (no separate field).
    """
    mode = aes_mode.lower()

    if mode == 'ccm':
        # CCM uses AESCCM, expects nonce of length 7..13 bytes
        nonce = os.urandom(13)  # typical
        aesccm = AESCCM(key, tag_length=16)
        ciphertext = aesccm.encrypt(nonce, plaintext, None)

        # AESCCM merges the tag with the ciphertext
        return {
            'mode': mode,
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    # For block cipher modes, we apply PKCS#7 if needed:
    if mode in ('ecb', 'cbc'):
        plaintext = _pkcs7_pad(plaintext)

    if mode == 'ecb':
        iv_or_nonce = None
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    elif mode == 'cbc':
        # Must be 16 bytes for AES
        iv_or_nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv_or_nonce), backend=default_backend())

    elif mode == 'ctr':
        # Must be 16 bytes (128 bits) for CTR in cryptography
        iv_or_nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv_or_nonce), backend=default_backend())

    elif mode == 'gcm':
        # Typically 12 bytes for GCM
        iv_or_nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv_or_nonce), backend=default_backend())

    else:
        raise ValueError(f"Unsupported AES mode '{aes_mode}'")

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    result = {
        'mode': mode,
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

    if mode == 'cbc' or mode == 'ctr':
        result['iv'] = base64.b64encode(iv_or_nonce).decode('utf-8')

    elif mode == 'gcm':
        result['nonce'] = base64.b64encode(iv_or_nonce).decode('utf-8')
        result['tag'] = base64.b64encode(encryptor.tag).decode('utf-8')

    return result


def decrypt_data(key: bytes, data_dict: dict) -> bytes:
    """
    Decrypt a ciphertext using the AES mode in data_dict['mode'].
    Supports: ECB, CBC, CTR, GCM, CCM.

    For CCM:
      - 'nonce'
      - 'ciphertext' (tag merged)
    For GCM:
      - 'nonce'
      - 'tag'
      - 'ciphertext'
    For CBC/CTR:
      - 'iv'
      - 'ciphertext'
    For ECB:
      - 'ciphertext'
    """
    mode = data_dict['mode'].lower()

    if mode == 'ccm':
        try:
            nonce = base64.b64decode(data_dict['nonce'])
            ciphertext = base64.b64decode(data_dict['ciphertext'])
            aesccm = AESCCM(key, tag_length=16)
            plaintext = aesccm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception:
            # We do not log anything to error.log
            raise

    # For other modes
    ciphertext = base64.b64decode(data_dict['ciphertext'])

    if mode == 'gcm':
        nonce = base64.b64decode(data_dict['nonce'])
        tag = base64.b64decode(data_dict['tag'])
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    elif mode == 'cbc':
        iv = base64.b64decode(data_dict['iv'])
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        # Remove PKCS7 padding
        plaintext = _pkcs7_unpad(plaintext)

    elif mode == 'ctr':
        iv = base64.b64decode(data_dict['iv'])
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    elif mode == 'ecb':
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        # Remove PKCS7 padding
        plaintext = _pkcs7_unpad(plaintext)

    else:
        raise ValueError(f"Unsupported AES mode '{mode}' for decryption.")

    return plaintext
