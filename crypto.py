# crypto.py
# Handles all cryptographic operations for the SecureClinical platform
# Implements: AES-256-GCM with AAD, RSA-2048 signatures, SHA-256 integrity hashing

import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ============================================================
# AES-256-GCM ENCRYPTION WITH AUTHENTICATED ADDITIONAL DATA
# ============================================================
# AAD (Authenticated Additional Data) binds contextual metadata
# to the ciphertext. If the ciphertext is moved to a different
# context (e.g., a different user or role), decryption fails.
# This is a key differentiator from basic AES-GCM implementations
# and directly supports GDPR Article 32 access control requirements.

def generate_aes_key():
    """
    Generate a cryptographically random 256-bit AES key.
    256-bit selected over 128-bit for alignment with NIST SP 800-57
    recommendations for long-term protection of sensitive health data.
    """
    return AESGCM.generate_key(bit_length=256)


def encrypt_data(key, plaintext, aad=None):
    """
    Encrypt data using AES-256-GCM with optional Authenticated Additional Data.
    
    AAD parameter allows binding of contextual metadata (e.g. username, role,
    filename) to the ciphertext without encrypting it. Any modification to the
    AAD or attempt to use ciphertext in a different context causes decryption
    to fail, providing cryptographic enforcement of access control.
    
    Args:
        key: 256-bit AES key (bytes)
        plaintext: string data to encrypt
        aad: optional context string (e.g. "researcher:alice:patient_data.txt")
    
    Returns:
        base64 encoded string of nonce + ciphertext + GCM auth tag
    """
    aesgcm = AESGCM(key)
    # Nonce must be unique per encryption - os.urandom provides
    # cryptographically secure randomness (96-bit as per NIST SP 800-38D)
    nonce = os.urandom(12)
    
    # Convert AAD to bytes if provided
    aad_bytes = aad.encode() if aad else None
    
    # GCM mode simultaneously encrypts and authenticates
    # The auth tag is automatically appended to ciphertext
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad_bytes)
    
    # Prepend nonce so it's available during decryption
    encrypted = base64.b64encode(nonce + ciphertext).decode()
    return encrypted


def decrypt_data(key, encrypted, aad=None):
    """
    Decrypt AES-256-GCM data. AAD must match what was used during encryption.
    GCM authentication tag verification happens automatically - if data has
    been tampered with or AAD doesn't match, an InvalidTag exception is raised.
    
    Args:
        key: 256-bit AES key (bytes)
        encrypted: base64 encoded encrypted string
        aad: must match the AAD used during encryption
    
    Returns:
        decrypted plaintext string
    
    Raises:
        Exception if authentication tag verification fails (tampering detected)
    """
    aesgcm = AESGCM(key)
    raw = base64.b64decode(encrypted.encode())
    
    # Extract nonce (first 12 bytes) and ciphertext+tag (remainder)
    nonce = raw[:12]
    ciphertext = raw[12:]
    
    aad_bytes = aad.encode() if aad else None
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad_bytes)
        return plaintext.decode()
    except Exception:
        raise Exception("Decryption failed: authentication tag mismatch. "
                       "Data may have been tampered with or AAD context is incorrect.")


# ============================================================
# SHA-256 INTEGRITY HASHING
# ============================================================
# Used for file/data integrity verification and audit log chaining.
# SHA-256 selected for collision resistance (2^128 security level)
# appropriate for integrity verification in clinical data contexts.

def hash_data(data):
    """
    Compute SHA-256 digest of a string.
    Used for data integrity verification - any modification to data
    produces a completely different hash value (avalanche effect).
    """
    return hashlib.sha256(data.encode()).hexdigest()


def verify_integrity(data, expected_hash):
    """
    Verify data integrity by comparing computed hash to expected hash.
    Returns True if data is unmodified, False if tampering is detected.
    """
    return hash_data(data) == expected_hash


# ============================================================
# RSA-2048 DIGITAL SIGNATURES
# ============================================================
# RSA is used exclusively for signing and key encapsulation operations,
# not bulk data encryption. RSA-2048 key operations are ~100x slower
# than AES-256-GCM for equivalent data volumes, making it unsuitable
# for bulk encryption but appropriate here where it is applied only to
# small payloads (signatures, key wrapping).
#
# PSS padding selected over PKCS1v15 as it provides provable security
# under the random oracle model and is recommended by NIST SP 800-131A.

def generate_rsa_keypair():
    """
    Generate RSA-2048 key pair.
    Private key: held by researcher, used to sign findings.
    Public key: shared with auditors for signature verification.
    
    public_exponent=65537 is the standard choice - it is a Fermat prime
    that provides efficient computation while maintaining security.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()


def sign_data(private_key, data):
    """
    Create RSA-PSS digital signature over data.
    Provides non-repudiation - only the holder of the private key
    could have produced this signature, satisfying GDPR requirements
    for accountability in processing special category health data.
    
    Args:
        private_key: RSA private key object
        data: string to sign
    
    Returns:
        base64 encoded signature string
    """
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(public_key, data, signature):
    """
    Verify RSA-PSS digital signature.
    Used by Auditors to confirm research findings were signed by
    the claimed Researcher and have not been modified since signing.
    
    Returns:
        True if signature is valid and data is unmodified
        False if signature is invalid or data has been tampered with
    """
    try:
        public_key.verify(
            base64.b64decode(signature.encode()),
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ============================================================
# RSA KEY ENCAPSULATION
# ============================================================
# AES keys are encrypted with the recipient's RSA public key before storage.
# This means the AES key (and therefore the data) can only be decrypted
# by the holder of the corresponding RSA private key - enforcing
# cryptographic access control beyond simple password protection.

def encrypt_aes_key_with_rsa(public_key, aes_key):
    """
    Wrap (encrypt) an AES key using RSA-OAEP.
    Allows secure transmission of AES session keys.
    OAEP padding with SHA-256 selected per NIST SP 800-131A recommendations.
    """
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()


def decrypt_aes_key_with_rsa(private_key, encrypted_key):
    """
    Unwrap (decrypt) an AES key using RSA private key.
    Only the holder of the private key can recover the AES key
    and therefore decrypt the associated data.
    """
    aes_key = private_key.decrypt(
        base64.b64decode(encrypted_key.encode()),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key