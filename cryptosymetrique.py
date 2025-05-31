from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
import binascii

def validate_hex(hex_str, expected_length):
    """Valide une chaîne hexadécimale et sa longueur en octets."""
    try:
        if len(hex_str) != expected_length * 2:  # 2 caractères hex = 1 octet
            return False
        binascii.unhexlify(hex_str)
        return True
    except binascii.Error:
        return False

def des_encrypt(text, key, mode, iv=None):
    """
    Chiffre un texte avec DES.
    Args:
        text (str): Texte en clair.
        key (str): Clé en hexadécimal (8 octets).
        mode (str): 'ECB' ou 'CBC'.
        iv (str, optional): IV en hexadécimal (8 octets, requis pour CBC).
    Returns:
        str: Texte chiffré en hexadécimal.
    Raises:
        ValueError: Si les entrées sont invalides.
    """
    if not text:
        raise ValueError("Texte invalide")
    if not validate_hex(key, 8):
        raise ValueError("Clé invalide (doit être 8 octets en hexadécimal)")
    if mode.upper() not in ['ECB', 'CBC']:
        raise ValueError("Mode invalide (doit être ECB ou CBC)")
    if mode.upper() == 'CBC' and (iv is None or not validate_hex(iv, 8)):
        raise ValueError("IV invalide (doit être 8 octets en hexadécimal pour CBC)")

    try:
        key_bytes = binascii.unhexlify(key)
        text_bytes = text.encode('utf-8')
        padded_text = pad(text_bytes, DES.block_size)

        if mode.upper() == 'ECB':
            cipher = DES.new(key_bytes, DES.MODE_ECB)
            encrypted = cipher.encrypt(padded_text)
        else:  # CBC
            iv_bytes = binascii.unhexlify(iv)
            cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
            encrypted = cipher.encrypt(padded_text)

        return encrypted.hex()
    except Exception as e:
        raise ValueError(f"Erreur lors du chiffrement DES : {str(e)}")

def aes_encrypt(text, key, mode, iv=None):
    """
    Chiffre un texte avec AES.
    Args:
        text (str): Texte en clair.
        key (str): Clé en hexadécimal (16, 24, ou 32 octets).
        mode (str): 'ECB' ou 'CBC'.
        iv (str, optional): IV en hexadécimal (16 octets, requis pour CBC).
    Returns:
        str: Texte chiffré en hexadécimal.
    Raises:
        ValueError: Si les entrées sont invalides.
    """
    if not text:
        raise ValueError("Texte invalide")
    if not (validate_hex(key, 16) or validate_hex(key, 24) or validate_hex(key, 32)):
        raise ValueError("Clé invalide (doit être 16, 24 ou 32 octets en hexadécimal)")
    if mode.upper() not in ['ECB', 'CBC']:
        raise ValueError("Mode invalide (doit être ECB ou CBC)")
    if mode.upper() == 'CBC' and (iv is None or not validate_hex(iv, 16)):
        raise ValueError("IV invalide (doit être 16 octets en hexadécimal pour CBC)")

    try:
        key_bytes = binascii.unhexlify(key)
        text_bytes = text.encode('utf-8')
        padded_text = pad(text_bytes, AES.block_size)

        if mode.upper() == 'ECB':
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            encrypted = cipher.encrypt(padded_text)
        else:
            iv_bytes = binascii.unhexlify(iv)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            encrypted = cipher.encrypt(padded_text)

        return encrypted.hex()
    except Exception as e:
        raise ValueError(f"Erreur lors du chiffrement AES : {str(e)}")