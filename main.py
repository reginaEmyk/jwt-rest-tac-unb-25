#%%
import hashlib
from typing import List


# key 
# The following discussion of HMAC security assumes the secret key has been obtained with
# 396 an acceptable security strength using a cryptographic random bit generator — see the
# 397 SP 800 90 series [19, 32, 33].

# JWT signature: user.timestamp and timestamp , hash it, encrypt (hmac, rsa)
# HMAC: msge
# RSA: user.timestamp and timestamp , hash it, encrypt 

BLOCK_SIZE = 512 # bits
MIN_KEY_SIZE = 128 # allows shorter keys https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf
KEY_LENGTH = 256
MAX_KEY_SIZE = BLOCK_SIZE

class Credentials:
    def __init__(self, name: str, pwd: str, key: str, tokens: List[str]):
        self.name = name
        self.pwd = pwd
        self.key = key
        self.tokens = tokens

    @classmethod
    def from_dict(cls, data: dict) -> 'Credentials':
        return cls(
            name=data.get("name"),
            pwd=data.get("pwd"),
            key=data.get("key"),
            tokens=data.get("tokens", [])
        )

# credenciais definidas em credentials.json 
def load_credentials(filename="credentials.json") -> Credentials | None:
    import os
    if not os.path.exists(filename):
        print(f"Error: {filename} not found.")
        return None
    with open(filename, 'r') as f:
        data = json.load(f)
        return Credentials.from_dict(data)


def hmac_sha256(key: bytes, message: bytes) -> bytes:    
    # Step 1, 2, 3: Normalize key to block size B
    if len(key) > BLOCK_SIZE:
         # Step 2
        key = hashlib.sha256(key).digest()
    if len(key) < BLOCK_SIZE:
        # Step 3
        key = key + b'\x00' * (BLOCK_SIZE - len(key)) 
    K0 = key  # Step 1/2/3 result

    # Step 4: K0 ⊕ ipad (0x36)
    ipad = bytes((x ^ 0x36) for x in K0)

    # Step 5: (K0 ⊕ ipad) || message
    step5 = ipad + message

    # Step 6: H((K0 ⊕ ipad) || message)
    inner_hash = hashlib.sha256(step5).digest()

    # Step 7: K0 ⊕ opad (0x5c)
    opad = bytes((x ^ 0x5c) for x in K0)

    # Step 8: (K0 ⊕ opad) || inner_hash
    step8 = opad + inner_hash

    # Step 9: Final HMAC = H(step8)
    return hashlib.sha256(step8).digest()

def test_hmac():
    ning = load_credentials()
    key = ning.key

    token = ning.tokens[0].encode('utf-8')

    pwd = "64d473a05b66bb916793217fcbcb6c2cddce166523fb54909cd9ba058f1e7b9b".encode('utf-8')

    print(hmac_sha256(pwd ,token) == hmac_sha256(pwd ,token))
    print(hmac_sha256(pwd ,token) == hmac_sha256( "64d473a05b66bb916793217fcbcb6c2cddce166523fb54909cd9ba058f1e7b9b".encode('utf-8'), "12 3".encode('utf-8')))
test_hmac()
#%%

def key_from_image():
    key_material = SHA-256(image_bytes)
    hmac_key = HKDF(
    input_key_material=key_material,
    salt=optional_salt,  # for additional security
    info=optional_context,  # binding the key to a specific use
    length=desired_key_length
    
)

# %%
def random_key() -> bytes:
    """
    Gera chave (não faz parte da função HMAC)
    """
    import os
    return os.urandom(KEY_LENGTH)

def base64url_encode(data: bytes) -> str:
    """
    Base64URL encoding for JWT (without padding)
    
    Args:
        data: Bytes to encode
        
    Returns:
        Base64URL encoded string
    """
    import base64
    return base64.urlsafe_b64encode(data).decode('utf-8').replace('=', '')

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib.parse import urlparse, parse_qs

# Armazenamento em memória (simula banco de dados)
items = []

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def _send_json_response(self, data, status=200):
        response = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/items':
            self._send_json_response(items)
        else:
            self._send_json_response({'error': 'Not Found'}, status=404)

    def do_POST(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/items':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(body)
                if 'name' in data:
                    item = {'id': len(items) + 1, 'name': data['name']}
                    items.append(item)
                    self._send_json_response(item, status=201)
                else:
                    self._send_json_response({'error': 'Missing "name" field'}, status=400)
            except json.JSONDecodeError:
                self._send_json_response({'error': 'Invalid JSON'}, status=400)
        else:
            self._send_json_response({'error': 'Not Found'}, status=404)


# Example usage for JWT
if __name__ == "__main__":
    # Generate a secure key (should be kept secret!)
    secret_key = random_key()
    print(f"Generated key (hex): {secret_key.hex()}")
    
    # Example JWT payload
    header = '{"alg":"HS256","typ":"JWT"}'
    payload = '{"sub":"1234567890","name":"John Doe","iat":1516239022}'
    
    # Prepare JWT components
    encoded_header = base64url_encode(header.encode('utf-8'))
    encoded_payload = base64url_encode(payload.encode('utf-8'))
    message_to_sign = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    
    # Create HMAC signature
    signature = hmac_sha256(secret_key, message_to_sign)
    encoded_signature = base64url_encode(signature)
    
    # Final JWT
    jwt = f"{encoded_header}.{encoded_payload}.{encoded_signature}"
    print(f"Example JWT: {jwt}")


def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Servidor rodando em http://localhost:{port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run()