from flask import Flask, request, jsonify
from crypto import caesar_encrypt, vigenere_encrypt, substitution_encrypt
from cryptosymetrique import * 
8 
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Autorise toutes les origines
DEFAULT_SUBSTITUTION_TABLE = {
    'a': 'q', 'b': 'w', 'c': 'e', 'd': 'r', 'e': 't', 'f': 'y', 'g': 'u',
    'h': 'i', 'i': 'o', 'j': 'p', 'k': 'a', 'l': 's', 'm': 'd', 'n': 'f',
    'o': 'g', 'p': 'h', 'q': 'j', 'r': 'k', 's': 'l', 't': 'z', 'u': 'x',
    'v': 'c', 'w': 'v', 'x': 'b', 'y': 'n', 'z': 'm'
}

@app.route('/caesar', methods=['POST'])
def caesar():
    data = request.get_json()
    text = data.get('text', '')
    shift = data.get('shift', 3)
    if not text or not isinstance(shift, int):
        return jsonify({'error': 'Texte ou shift invalide'}), 400
    encrypted = caesar_encrypt(text, shift)
    return jsonify({'encrypted': encrypted})

@app.route('/vigenere', methods=['POST'])
def vigenere():
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', 'key')
    if not text or not key.isalpha():
        return jsonify({'error': 'Texte ou clé invalide'}), 400
    encrypted = vigenere_encrypt(text, key)
    return jsonify({'encrypted': encrypted})

@app.route('/substitution', methods=['POST'])
def substitution():
    data = request.get_json()
    text = data.get('text', '')
    substitution_table = data.get('substitution_table', DEFAULT_SUBSTITUTION_TABLE)
    if not text or not isinstance(substitution_table, dict):
        return jsonify({'error': 'Texte ou table de substitution invalide'}), 400
    encrypted = substitution_encrypt(text, substitution_table)
    return jsonify({'encrypted': encrypted})


# Routes pour DES
@app.route('/des', methods=['POST'])
def des():
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'ECB').lower()
    iv = data.get('iv', '')

    try:
        encrypted = des_encrypt(text, key, mode, iv)
        return jsonify({'encrypted': encrypted})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Erreur serveur : {str(e)}'}), 500

# Routes pour AES
@app.route('/aes', methods=['POST'])
def aes():
    data = request.get_json()
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'ECB').lower()
    iv = data.get('iv', '')

    try:
        encrypted = aes_encrypt(text, key, mode, iv)
        return jsonify({'encrypted': encrypted})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Erreur serveur : {str(e)}'}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Render te donne un port dans cette variable
    app.run(host='0.0.0.0', port=port)
