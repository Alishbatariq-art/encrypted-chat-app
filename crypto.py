from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
import base64

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem.decode(), pub_pem.decode()

def generate_aes_key():
    return Fernet.generate_key().decode()

def encrypt_aes_key_with_rsa(aes_key, public_key_pem):
    pub_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted = pub_key.encrypt(
        aes_key.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode()

def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_pem):
    priv_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    decrypted = priv_key.decrypt(
        base64.b64decode(encrypted_aes_key),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted.decode()

def encrypt_message(message, aes_key):
    f = Fernet(aes_key.encode())
    return f.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, aes_key):
    f = Fernet(aes_key.encode())
    return f.decrypt(encrypted_message.encode()).decode()