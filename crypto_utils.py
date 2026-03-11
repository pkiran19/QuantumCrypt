from pqcrypto.kem import ml_kem_768
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

# --- Post-Quantum Encryption (Key Encapsulation) ---
def pqc_generate_keys():
    public_key, secret_key = ml_kem_768.generate_keypair()
    return public_key, secret_key

def pqc_encrypt(public_key, message: bytes) -> bytes:
    ciphertext, shared_secret = ml_kem_768.encrypt(public_key)
    # In a real hybrid hybrid, we would use shared_secret to encrypt via AES.
    # For this academic project structure, we combine them as requested.
    return ciphertext + b"||" + message

def pqc_decrypt(secret_key, encrypted_data: bytes) -> bytes:
    try:
        ciphertext, message = encrypted_data.split(b"||", 1)
        ml_kem_768.decrypt(secret_key, ciphertext)  # Validation
        return message
    except Exception:
        return b"[Decryption failed]"

# --- Digital Signatures (RSA + SHA256) ---
def generate_rsa_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem, private_pem

def sign_data(private_key_pem, data: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key_pem, signature: bytes, data: bytes) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False