def caesar_encrypt(text, shift):
    """Chiffrement César : décalage des lettres par 'shift'."""
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) + shift - ascii_offset) % 26 + ascii_offset)
        else:
            result += char
    return result

def vigenere_encrypt(text, key):
    """Chiffrement Vigenère : utilise une clé répétée."""
    result = ""
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - 97
            result += chr((ord(char) + shift - ascii_offset) % 26 + ascii_offset)
            key_index += 1
        else:
            result += char
    return result

def substitution_encrypt(text, substitution_table):
    """Chiffrement par substitution : remplace chaque lettre selon la table."""
    result = ""
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            char_lower = char.lower()
            result += substitution_table[char_lower].upper() if is_upper else substitution_table[char_lower]
        else:
            result += char
    return result