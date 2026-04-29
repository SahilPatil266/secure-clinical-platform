# hsm.py
# Software HSM (Hardware Security Module) Abstraction Layer
# for the SecureClinical platform.
#
# A Hardware Security Module is a physical device that stores private keys
# and performs cryptographic operations internally - the private key never
# leaves the hardware. This provides the strongest possible protection for
# cryptographic key material.
#
# This module implements a software abstraction layer that mirrors the
# interface a real HSM would expose. The application code interacts with
# the HSMInterface class rather than directly with key files, meaning:
#
# 1. Private keys are never directly accessible to application code
#    All key operations are mediated through this interface
#
# 2. The backend can be swapped without changing application code
#    In production: replace SoftwareHSMBackend with a real HSM backend
#    (e.g. PKCS#11 interface to a Thales nShield or AWS CloudHSM)
#    No changes to roles.py, auth.py, or any other module required
#
# 3. All cryptographic operations are logged automatically
#    The interface enforces audit logging on every key operation,
#    satisfying GDPR Article 5(2) accountability requirements
#
# Real HSM context:
# In NHS clinical deployments, DSPT requirement 9.4.1 mandates that
# cryptographic keys protecting special category health data should be
# stored in hardware-protected key stores. AWS CloudHSM, Azure Dedicated
# HSM, and Thales Luna HSMs are commonly used in NHS infrastructure.
# The PKCS#11 standard defines the API that real HSMs expose - this
# abstraction layer mirrors that interface pattern.
#
# Limitation acknowledgement:
# This implementation uses PEM files as the backend rather than real
# HSM hardware. The architectural pattern is production-ready, but the
# security guarantees of a real HSM (tamper-evident hardware, key
# non-exportability) cannot be replicated in software. In a production
# deployment, SoftwareHSMBackend would be replaced with a PKCS#11
# backend connecting to certified HSM hardware.

import os
from audit import log_event
from key_manager import load_private_key, load_public_key
from crypto import sign_data, verify_signature, encrypt_aes_key_with_rsa
from crypto import decrypt_aes_key_with_rsa


# ============================================================
# HSM BACKEND INTERFACE
# ============================================================
# Defines the contract that any HSM backend must implement.
# This is the abstraction boundary - swap the backend class
# to change the underlying key storage mechanism.

class HSMBackend:
    """
    Abstract base class defining the HSM backend interface.

    Any concrete backend (software, PKCS#11, cloud HSM) must
    implement these methods. The application never calls
    these directly - always goes through HSMInterface.
    """

    def load_private_key(self, username, password):
        """Load private key material. In real HSM, key never leaves hardware."""
        raise NotImplementedError

    def load_public_key(self, username):
        """Load public key material."""
        raise NotImplementedError

    def sign(self, username, password, data):
        """Sign data using the private key for username."""
        raise NotImplementedError

    def decrypt_key(self, username, password, encrypted_aes_key):
        """Unwrap an AES key using the RSA private key for username."""
        raise NotImplementedError

    def encrypt_key(self, username, aes_key):
        """Wrap an AES key using the RSA public key for username."""
        raise NotImplementedError


# ============================================================
# SOFTWARE HSM BACKEND
# ============================================================
# Concrete implementation using PEM files.
# In production, replace this class with a PKCS#11 backend.

class SoftwareHSMBackend(HSMBackend):
    """
    Software backend for the HSM abstraction layer.

    Uses PEM files stored in the keys/ directory as the key store.
    Private keys are encrypted at rest with the user's password,
    providing a software approximation of HSM key protection.

    Production replacement: PKCSHSMBackend using python-pkcs11
    library to interface with certified HSM hardware via the
    PKCS#11 standard API.
    """

    def load_private_key(self, username, password):
        """
        Load encrypted private key from PEM file.
        In a real HSM, the private key would never leave the hardware -
        this is the fundamental limitation of the software backend.
        """
        return load_private_key(username, password)

    def load_public_key(self, username):
        """Load public key from PEM file."""
        return load_public_key(username)

    def sign(self, username, password, data):
        """
        Sign data by loading private key and performing RSA-PSS signature.
        In a real HSM, the signing operation would happen inside the hardware
        and only the signature would be returned - the private key would
        never be accessible to this code.
        """
        private_key = self.load_private_key(username, password)
        return sign_data(private_key, data)

    def decrypt_key(self, username, password, encrypted_aes_key):
        """
        Unwrap an AES key using RSA private key.
        In a real HSM, key unwrapping would happen inside the hardware.
        """
        private_key = self.load_private_key(username, password)
        return decrypt_aes_key_with_rsa(private_key, encrypted_aes_key)

    def encrypt_key(self, username, aes_key):
        """
        Wrap an AES key using RSA public key.
        Public key operations do not require HSM hardware.
        """
        public_key = self.load_public_key(username)
        return encrypt_aes_key_with_rsa(public_key, aes_key)


# ============================================================
# HSM INTERFACE
# ============================================================
# This is what application code uses.
# All operations are mediated, logged, and backend-agnostic.

class HSMInterface:
    """
    Application-facing HSM interface.

    Provides a clean API for all cryptographic key operations,
    enforcing audit logging on every operation and abstracting
    the underlying key storage backend.

    Usage:
        hsm = HSMInterface(username, role)
        signature = hsm.sign(data, password)
        aes_key = hsm.unwrap_key(encrypted_key, password)

    To switch to a real HSM backend:
        hsm = HSMInterface(username, role, backend=PKCSHSMBackend())
    """

    def __init__(self, username, role, backend=None):
        """
        Initialise HSM interface for a specific user.

        Args:
            username: the authenticated user
            role: their role (for audit logging)
            backend: HSM backend to use (defaults to SoftwareHSMBackend)
                     In production, pass a PKCS#11 backend here
        """
        self.username = username
        self.role = role
        # Default to software backend - swap here for production HSM
        self.backend = backend if backend else SoftwareHSMBackend()
        self._backend_type = type(self.backend).__name__

    def sign(self, data, password):
        """
        Sign data using the user's private key.

        The private key operation is mediated through the backend -
        application code never directly accesses key material.
        Every signing operation is recorded in the audit log.

        Args:
            data: string to sign
            password: user's password to authorise the key operation

        Returns:
            base64 encoded signature string
        """
        try:
            signature = self.backend.sign(self.username, password, data)

            log_event(
                self.username, self.role, "HSM_SIGN",
                f"Data signed via {self._backend_type}. "
                f"Data length: {len(data)} chars"
            )

            return signature

        except Exception as e:
            log_event(
                self.username, self.role, "HSM_SIGN_FAILED",
                f"Signing operation failed via {self._backend_type}: {str(e)}"
            )
            raise

    def verify(self, signer_username, data, signature):
        """
        Verify a signature using a user's public key.

        Public key operations do not require password authentication.
        Used by Auditors to verify signatures without needing
        access to any private key material.

        Args:
            signer_username: whose public key to use for verification
            data: the original data that was signed
            signature: the signature to verify

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key = self.backend.load_public_key(signer_username)
            result = verify_signature(public_key, data, signature)

            log_event(
                self.username, self.role, "HSM_VERIFY",
                f"Signature verification for {signer_username} via "
                f"{self._backend_type}: {'VALID' if result else 'INVALID'}"
            )

            return result

        except Exception as e:
            log_event(
                self.username, self.role, "HSM_VERIFY_FAILED",
                f"Verification failed via {self._backend_type}: {str(e)}"
            )
            return False

    def wrap_key(self, recipient_username, aes_key):
        """
        Wrap (encrypt) an AES key for a recipient using their public key.

        Used during file encryption to protect the AES key for
        each authorised recipient. Public key operation - no password needed.

        Args:
            recipient_username: whose public key to use
            aes_key: raw AES key bytes to protect

        Returns:
            base64 encoded encrypted key string
        """
        try:
            encrypted_key = self.backend.encrypt_key(recipient_username, aes_key)

            log_event(
                self.username, self.role, "HSM_WRAP_KEY",
                f"AES key wrapped for {recipient_username} via "
                f"{self._backend_type}"
            )

            return encrypted_key

        except Exception as e:
            log_event(
                self.username, self.role, "HSM_WRAP_KEY_FAILED",
                f"Key wrapping failed for {recipient_username}: {str(e)}"
            )
            raise

    def unwrap_key(self, encrypted_aes_key, password):
        """
        Unwrap (decrypt) an AES key using the user's private key.

        Used during file decryption to recover the AES key.
        Requires password to authorise the private key operation.
        Every unwrap operation is recorded in the audit log.

        In a real HSM, the unwrapping operation happens inside the
        hardware and only the plaintext AES key is returned.

        Args:
            encrypted_aes_key: base64 encoded wrapped AES key
            password: user's password to authorise the operation

        Returns:
            raw AES key bytes
        """
        try:
            aes_key = self.backend.decrypt_key(
                self.username, password, encrypted_aes_key
            )

            log_event(
                self.username, self.role, "HSM_UNWRAP_KEY",
                f"AES key unwrapped via {self._backend_type}"
            )

            return aes_key

        except Exception as e:
            log_event(
                self.username, self.role, "HSM_UNWRAP_KEY_FAILED",
                f"Key unwrap failed via {self._backend_type}: {str(e)}"
            )
            raise

    def get_backend_info(self):
        """
        Return information about the current HSM backend.
        Used for system status display and audit purposes.
        """
        return {
            "backend_type": self._backend_type,
            "username": self.username,
            "production_ready": isinstance(
                self.backend, SoftwareHSMBackend
            ) is False,
            "note": (
                "Software backend in use. For production clinical deployment, "
                "replace SoftwareHSMBackend with PKCS#11 backend connecting "
                "to certified HSM hardware (e.g. AWS CloudHSM, Thales Luna)."
            )
        }