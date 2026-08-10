"""
core/decryptor.py
Implements the encryption decryption manager, supporting plugin-like handlers
such as AES, XOR, and custom algorithms. Requires key input.
"""

import base64
from typing import Dict, Any, Optional


def decrypt_xor(data: bytes, key: str) -> Optional[bytes]:
    """Decrypt data using XOR key repetition."""
    if not key:
        return None
    key_bytes = key.encode("utf-8")
    decrypted = bytearray(len(data))
    for i in range(len(data)):
        decrypted[i] = data[i] ^ key_bytes[i % len(key_bytes)]
    return bytes(decrypted)


def decrypt_aes(data: bytes, key: str) -> Optional[bytes]:
    """
    Decrypt data using AES. Since python standard libraries don't include PyCryptodome by default
    and we cannot run dynamic network installations, we use a pure-python minimal AES or standard fallback.
    We'll implement a clean, safe AES decryption handler using cryptography if available, or zlib/xor fallback.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        # Assume key is 16/24/32 bytes. Pad key if necessary.
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < 16:
            key_bytes = key_bytes.ljust(16, b"\x00")
        elif len(key_bytes) < 24:
            key_bytes = key_bytes.ljust(24, b"\x00")
        else:
            key_bytes = key_bytes[:32].ljust(32, b"\x00")

        # Assume IV is the first 16 bytes of data
        if len(data) < 17:
            return None
        iv = data[:16]
        cipher_text = data[16:]

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(cipher_text) + decryptor.finalize()

        # Remove PKCS7 padding
        pad_len = decrypted[-1]
        if 0 < pad_len <= 16:
            return decrypted[:-pad_len]
        return decrypted
    except Exception:
        # Fallback decryption simulation or cryptography not installed
        return None


class DecryptionManager:
    """Decryption manager supporting multiple encryption formats with user keys."""

    def __init__(self) -> None:
        pass

    def identify_algorithm(self, data: bytes) -> str:
        """Heuristically identify the decryption algorithm (XOR, AES, or UNKNOWN)."""
        if data.startswith(b"AES"):
            return "AES"
        # High entropy but not structural binary could be XOR/AES
        return "XOR"

    def decrypt(self, file_path: str, key: str, algo: Optional[str] = None) -> Dict[str, Any]:
        """
        Decrypt file using user-provided key.
        Returns dict with success status, decrypted content, algorithm, and details.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            return {"success": False, "error": f"Failed to read file: {e}"}

        if not algo:
            algo = self.identify_algorithm(data)

        decrypted_bytes = None
        if algo == "AES":
            decrypted_bytes = decrypt_aes(data, key)
        elif algo == "XOR":
            decrypted_bytes = decrypt_xor(data, key)

        if not decrypted_bytes:
            # Try XOR as a last fallback
            decrypted_bytes = decrypt_xor(data, key)

        if decrypted_bytes:
            # Verify if decrypted bytes are clean readable text
            try:
                text = decrypted_bytes.decode("utf-8")
                printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
                if len(text) > 0 and (printable / len(text)) > 0.8:
                    return {
                        "success": True,
                        "decrypted_content": text,
                        "algorithm": algo,
                        "details": "Decryption successful.",
                    }
            except Exception:
                pass

        return {
            "success": False,
            "error": "Decryption failed. Invalid key or unsupported format.",
        }
