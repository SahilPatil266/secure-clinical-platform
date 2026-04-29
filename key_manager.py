# key_manager.py
# Handles RSA key pair generation, encrypted storage, and retrieval.
# Also implements key rotation warnings based on key age.
#
# Key design decisions:
# - Private keys are stored encrypted with a password (PEM + AES-256-CBC)
#   meaning even if the keys/ folder is compromised, private keys cannot
#   be used without the password - two independent security layers
# - AES session keys are stored encrypted with each authorised recipient's
#   RSA public key, implementing multi-recipient key encapsulation
#   Only the intended recipient can recover the AES key using their
#   own private key - no shared secrets required
# - Key creation timestamps enable rotation warnings
#   Rotation period set to 60 days given Article 9 health data sensitivity
#   (reduced from the standard 90-day recommendation in NIST SP 800-57
#   to reflect the heightened sensitivity of special category health data)

import os
import json
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key
)
from crypto import generate_rsa_keypair, encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa

KEYS_DIR = "keys"
KEY_METADATA_FILE = "key_metadata.json"
KEY_ROTATION_DAYS = 60  # Reduced from 90 to 60 days given Article 9 health data sensitivity


def _ensure_keys_dir():
    """Create keys directory if it doesn't exist."""
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)


def _load_metadata():
    """Load key metadata (creation timestamps) from file."""
    if os.path.exists(KEY_METADATA_FILE):
        with open(KEY_METADATA_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_metadata(metadata):
    """Save key metadata to file."""
    with open(KEY_METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=4)


def generate_user_keys(username, password):
    """
    Generate and store an RSA-2048 key pair for a user.

    Private key is encrypted with the user's password using AES-256-CBC
    before being written to disk. This ensures that compromise of the
    keys/ directory alone is insufficient to use the private key -
    the password is also required, providing defence in depth.

    Args:
        username: used to name the key files
        password: used to encrypt the private key at rest
    """
    _ensure_keys_dir()

    private_key, public_key = generate_rsa_keypair()

    # Serialize private key to PEM format encrypted with user password
    # BestAvailableEncryption uses AES-256-CBC with the provided password
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode()
        )
    )

    # Serialize public key to PEM format (no encryption needed)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write keys to files
    with open(f"{KEYS_DIR}/{username}_private.pem", "wb") as f:
        f.write(private_pem)

    with open(f"{KEYS_DIR}/{username}_public.pem", "wb") as f:
        f.write(public_pem)

    # Record key creation timestamp for rotation tracking
    metadata = _load_metadata()
    metadata[username] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "key_size": 2048
    }
    _save_metadata(metadata)

    print(f"  [+] RSA-2048 key pair generated for {username}")


def load_private_key(username, password):
    """
    Load and decrypt a user's RSA private key from disk.

    Args:
        username: identifies which key file to load
        password: required to decrypt the private key

    Returns:
        RSA private key object

    Raises:
        Exception if password is wrong or key file does not exist
    """
    key_path = f"{KEYS_DIR}/{username}_private.pem"

    if not os.path.exists(key_path):
        raise Exception(f"No private key found for {username}.")

    with open(key_path, "rb") as f:
        private_pem = f.read()

    try:
        private_key = load_pem_private_key(
            private_pem,
            password=password.encode()
        )
        return private_key
    except Exception:
        raise Exception(
            "Failed to load private key - "
            "incorrect password or corrupted key file."
        )


def load_public_key(username):
    """
    Load a user's RSA public key from disk.
    Public keys are unencrypted and can be loaded without a password.

    Args:
        username: identifies which key file to load

    Returns:
        RSA public key object
    """
    key_path = f"{KEYS_DIR}/{username}_public.pem"

    if not os.path.exists(key_path):
        raise Exception(f"No public key found for {username}.")

    with open(key_path, "rb") as f:
        public_pem = f.read()

    return load_pem_public_key(public_pem)


def check_key_rotation(username):
    """
    Check if a user's RSA key pair is due for rotation and display
    a countdown tracker showing days remaining until mandatory rotation.

    Rotation period set to 60 days reflecting the heightened sensitivity
    of Article 9 GDPR special category health data processed by this system.
    This is more conservative than the standard 90-day recommendation in
    NIST SP 800-57, justified by the clinical research context where
    key compromise could expose sensitive patient health records.

    In a production deployment this check would be automated and triggered
    by a scheduled process rather than requiring user-initiated action.
    The current implementation provides the warning mechanism and rotation
    logic that a production scheduler would invoke automatically.

    Returns:
        (bool, message) - True if rotation overdue, with status message
    """
    metadata = _load_metadata()

    if username not in metadata:
        return False, "No key metadata found."

    created_at = datetime.fromisoformat(metadata[username]["created_at"])
    now = datetime.now(timezone.utc)
    age_days = (now - created_at).days
    days_remaining = KEY_ROTATION_DAYS - age_days
    rotation_count = metadata[username].get("rotation_count", 0)

    # Build a visual progress tracker
    # Shows how far through the 60-day cryptoperiod the key is
    filled = min(int((age_days / KEY_ROTATION_DAYS) * 20), 20)
    empty = 20 - filled
    bar = f"[{'█' * filled}{'░' * empty}]"

    if age_days >= KEY_ROTATION_DAYS:
        return True, (
            f"KEY ROTATION OVERDUE\n"
            f"  Cryptoperiod : {KEY_ROTATION_DAYS} days\n"
            f"  Key age      : {age_days} days\n"
            f"  Overdue by   : {age_days - KEY_ROTATION_DAYS} days\n"
            f"  Progress     : {bar} EXPIRED\n"
            f"  Rotations    : {rotation_count} previous rotation(s)\n"
            f"  Action       : Select 'Rotate RSA keys' from your menu\n"
            f"  Reference    : NIST SP 800-57 cryptoperiod guidelines"
        )
    elif days_remaining <= 10:
        return False, (
            f"KEY ROTATION DUE SOON\n"
            f"  Cryptoperiod : {KEY_ROTATION_DAYS} days\n"
            f"  Key age      : {age_days} days\n"
            f"  Days left    : {days_remaining} days\n"
            f"  Progress     : {bar} {int((age_days/KEY_ROTATION_DAYS)*100)}%\n"
            f"  Rotations    : {rotation_count} previous rotation(s)\n"
            f"  Action       : Consider rotating your keys soon"
        )
    else:
        return False, (
            f"Key rotation status: OK\n"
            f"  Cryptoperiod : {KEY_ROTATION_DAYS} days\n"
            f"  Key age      : {age_days} days\n"
            f"  Days left    : {days_remaining} days until rotation due\n"
            f"  Progress     : {bar} {int((age_days/KEY_ROTATION_DAYS)*100)}%\n"
            f"  Rotations    : {rotation_count} previous rotation(s)"
        )


def store_encrypted_aes_key_for_users(usernames, data_filename, aes_key):
    """
    Encrypt and store an AES key for multiple authorised recipients.

    Implements multi-recipient key encapsulation - the same AES key is
    wrapped independently with each recipient's RSA public key.
    Each authorised user can decrypt using only their own private key,
    without knowledge of other users' credentials.

    This design enforces GDPR Article 5(1)(c) data minimisation -
    each user accesses data via their own cryptographic identity,
    providing an auditable access trail without shared secrets.

    This is analogous to how PGP encrypts email to multiple recipients -
    the message is encrypted once but the session key is wrapped
    separately for each recipient.

    Args:
        usernames: list of usernames who should have access
        data_filename: identifier for the file this key belongs to
        aes_key: the raw AES key bytes to protect
    """
    key_store_file = f"{KEYS_DIR}/aes_keys.json"
    if os.path.exists(key_store_file):
        with open(key_store_file, "r") as f:
            key_store = json.load(f)
    else:
        key_store = {}

    # Wrap the AES key separately for each authorised recipient
    for username in usernames:
        try:
            public_key = load_public_key(username)
            encrypted_key = encrypt_aes_key_with_rsa(public_key, aes_key)
            key_store[f"{username}:{data_filename}"] = encrypted_key
            print(f"  [+] AES key wrapped for {username}")
        except Exception as e:
            print(f"  [!] Could not wrap key for {username}: {e}")

    with open(key_store_file, "w") as f:
        json.dump(key_store, f, indent=4)


def retrieve_aes_key(owner_username, data_filename, password):
    """
    Retrieve and decrypt an AES key for a specific file.

    The requesting user must have been an authorised recipient when
    the file was encrypted. They use their own private key (protected
    by their own password) to unwrap the AES key.

    No shared secrets required - each user's access is independent
    and cryptographically enforced. An unauthorised user attempting
    to access a file they were not granted access to will receive
    an access denied error regardless of their role.

    Args:
        owner_username: the user requesting access
        data_filename: which file's AES key to retrieve
        password: user's own password to decrypt their RSA private key

    Returns:
        raw AES key bytes

    Raises:
        Exception if user is not an authorised recipient
    """
    key_store_file = f"{KEYS_DIR}/aes_keys.json"

    if not os.path.exists(key_store_file):
        raise Exception("No AES key store found.")

    with open(key_store_file, "r") as f:
        key_store = json.load(f)

    key_id = f"{owner_username}:{data_filename}"
    if key_id not in key_store:
        raise Exception(
            f"Access denied: {owner_username} is not an "
            f"authorised recipient for {data_filename}."
        )

    encrypted_key = key_store[key_id]
    private_key = load_private_key(owner_username, password)
    return decrypt_aes_key_with_rsa(private_key, encrypted_key)

def rotate_user_keys(username, current_password, new_password):
    """
    Perform full RSA key rotation for a user.

    Key rotation process:
    1. Load all AES keys currently wrapped for this user
    2. Decrypt each AES key using the OLD private key
    3. Generate a new RSA key pair
    4. Re-encrypt each AES key using the NEW public key
    5. Archive the old key pair (retained for legacy decryption if needed)
    6. Save the new key pair as the active keys
    7. Update key metadata timestamp

    This implements NIST SP 800-57 cryptoperiod management for
    special category health data. The 60-day rotation period reflects
    the heightened sensitivity of Article 9 GDPR data processed
    by this system.

    Old keys are archived rather than deleted because:
    - Data encrypted before rotation still needs the old key to decrypt
    - Regulatory requirements may mandate retention of cryptographic
      material for audit purposes
    - Immediate deletion could cause data loss if rotation fails midway

    Args:
        username: user whose keys to rotate
        current_password: current password to decrypt old private key
        new_password: new password to encrypt new private key
                     (can be same as current_password)

    Returns:
        True if rotation successful, False otherwise
    """
    _ensure_keys_dir()

    print(f"\n  [*] Starting key rotation for {username}...")

    try:
        # Step 1 - Load old private key
        print(f"  [*] Loading current private key...")
        old_private_key = load_private_key(username, current_password)
        print(f"  [+] Current private key loaded successfully.")

        # Step 2 - Find all AES keys wrapped for this user
        key_store_file = f"{KEYS_DIR}/aes_keys.json"
        if os.path.exists(key_store_file):
            with open(key_store_file, "r") as f:
                key_store = json.load(f)
        else:
            key_store = {}

        # Find all entries belonging to this user
        user_keys = {
            k: v for k, v in key_store.items()
            if k.startswith(f"{username}:")
        }

        print(f"  [*] Found {len(user_keys)} AES key(s) to re-wrap...")

        # Step 3 - Decrypt all existing AES keys with old private key
        decrypted_aes_keys = {}
        for key_id, encrypted_key in user_keys.items():
            try:
                aes_key = decrypt_aes_key_with_rsa(old_private_key,
                                                    encrypted_key)
                decrypted_aes_keys[key_id] = aes_key
                filename = key_id.split(":", 1)[1]
                print(f"  [+] AES key recovered for: {filename}")
            except Exception as e:
                print(f"  [!] Could not recover AES key for {key_id}: {e}")

        # Step 4 - Archive old key pair before generating new one
        old_private_path = f"{KEYS_DIR}/{username}_private.pem"
        old_public_path = f"{KEYS_DIR}/{username}_public.pem"
        archive_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        archive_private = f"{KEYS_DIR}/{username}_private_archived_{archive_timestamp}.pem"
        archive_public = f"{KEYS_DIR}/{username}_public_archived_{archive_timestamp}.pem"

        # Copy old keys to archive
        with open(old_private_path, "rb") as f:
            old_private_pem = f.read()
        with open(archive_private, "wb") as f:
            f.write(old_private_pem)

        with open(old_public_path, "rb") as f:
            old_public_pem = f.read()
        with open(archive_public, "wb") as f:
            f.write(old_public_pem)

        print(f"  [+] Old keys archived as:")
        print(f"      {archive_private}")
        print(f"      {archive_public}")

        # Step 5 - Generate new RSA key pair
        print(f"  [*] Generating new RSA-2048 key pair...")
        new_private_key, new_public_key = generate_rsa_keypair()

        # Save new private key encrypted with new password
        new_private_pem = new_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                new_password.encode()
            )
        )

        new_public_pem = new_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(old_private_path, "wb") as f:
            f.write(new_private_pem)

        with open(old_public_path, "wb") as f:
            f.write(new_public_pem)

        print(f"  [+] New RSA-2048 key pair generated and saved.")

        # Step 6 - Re-wrap all AES keys with new public key
        print(f"  [*] Re-wrapping AES keys with new public key...")
        for key_id, aes_key in decrypted_aes_keys.items():
            new_encrypted_key = encrypt_aes_key_with_rsa(
                new_public_key, aes_key
            )
            key_store[key_id] = new_encrypted_key
            filename = key_id.split(":", 1)[1]
            print(f"  [+] AES key re-wrapped for: {filename}")

        # Save updated key store
        with open(key_store_file, "w") as f:
            json.dump(key_store, f, indent=4)

        # Step 7 - Update metadata timestamp
        metadata = _load_metadata()
        metadata[username] = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "key_size": 2048,
            "rotation_count": metadata.get(username, {}).get(
                "rotation_count", 0) + 1,
            "last_rotated": datetime.now(timezone.utc).isoformat()
        }
        _save_metadata(metadata)

        print(f"\n  [+] Key rotation completed successfully.")
        print(f"  [+] Rotation count: {metadata[username]['rotation_count']}")
        print(f"  [+] Old keys archived for legacy decryption if needed.")

        return True

    except Exception as e:
        print(f"\n  [!] Key rotation failed: {e}")
        print(f"  [!] Original keys preserved - no data loss occurred.")
        return False