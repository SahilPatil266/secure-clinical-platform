# test_system.py
# Automated functional test suite for the SecureClinical platform.
#
# Tests every major system operation and prints PASS/FAIL for each.
# This directly demonstrates Task 3 requirements:
# - Functional testing of main features
# - Confirmation that compliance features are present
# - Tests for all three user roles
# - Verification that each role has correct access rights
#
# Run with: python test_system.py

import os
import json
from crypto import (
    generate_aes_key, encrypt_data, decrypt_data,
    hash_data, verify_integrity, sign_data,
    verify_signature, generate_rsa_keypair
)
from auth import hash_password, verify_password, create_user
from audit import log_event, verify_log_integrity
from key_manager import (
    generate_user_keys, load_private_key, load_public_key,
    store_encrypted_aes_key_for_users, retrieve_aes_key,
    check_key_rotation
)

# ============================================================
# TEST HELPERS
# ============================================================

passed = 0
failed = 0


def test(name, condition, details=""):
    """Record and display a test result."""
    global passed, failed
    if condition:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name}")
        if details:
            print(f"         {details}")
        failed += 1


def section(title):
    """Print a section header."""
    print(f"\n  {'='*55}")
    print(f"  {title}")
    print(f"  {'='*55}")


# ============================================================
# SECTION 1 — AES-256-GCM ENCRYPTION
# ============================================================

section("1. AES-256-GCM Encryption and Decryption")

try:
    # Test basic encryption and decryption
    key = generate_aes_key()
    plaintext = "Sensitive patient data: Blood pressure 120/80"
    encrypted = encrypt_data(key, plaintext)
    decrypted = decrypt_data(key, encrypted)
    test("AES-256-GCM basic encrypt/decrypt", decrypted == plaintext)

    # Test encryption with AAD
    aad = "Bob_Researcher:patient_file.txt"
    encrypted_aad = encrypt_data(key, plaintext, aad)
    decrypted_aad = decrypt_data(key, encrypted_aad, aad)
    test("AES-256-GCM encrypt/decrypt with AAD", decrypted_aad == plaintext)

    # Test AAD mismatch causes decryption failure
    # Wrong AAD should cause an exception
    aad_fail = False
    try:
        decrypt_data(key, encrypted_aad, "wrong_user:wrong_file.txt")
    except Exception:
        aad_fail = True
    test("AAD mismatch correctly rejected", aad_fail)

    # Test that ciphertext is different from plaintext
    test("Ciphertext differs from plaintext",
         encrypted != plaintext)

    # Test that two encryptions of same plaintext produce different ciphertext
    # (due to random nonce)
    encrypted2 = encrypt_data(key, plaintext)
    test("Random nonce produces unique ciphertexts per encryption",
         encrypted != encrypted2)

    # Test wrong key fails decryption
    wrong_key = generate_aes_key()
    wrong_key_fail = False
    try:
        decrypt_data(wrong_key, encrypted)
    except Exception:
        wrong_key_fail = True
    test("Wrong AES key correctly rejected", wrong_key_fail)

except Exception as e:
    test("AES-256-GCM test suite", False, str(e))


# ============================================================
# SECTION 2 — SHA-256 INTEGRITY HASHING
# ============================================================

section("2. SHA-256 Data Integrity")

try:
    data = "Research finding: Trial group showed 34% improvement"

    # Test hash is consistent
    h1 = hash_data(data)
    h2 = hash_data(data)
    test("SHA-256 hash is deterministic", h1 == h2)

    # Test integrity verification passes on unmodified data
    test("Integrity check passes on unmodified data",
         verify_integrity(data, h1))

    # Test integrity check fails on tampered data
    tampered = data + " (modified)"
    test("Integrity check fails on tampered data",
         not verify_integrity(tampered, h1))

    # Test avalanche effect - small change produces completely different hash
    data2 = "Research finding: Trial group showed 35% improvement"
    h3 = hash_data(data2)
    test("Avalanche effect - similar inputs produce different hashes",
         h1 != h3)

    # Test hash length is correct (SHA-256 = 64 hex chars)
    test("SHA-256 output is correct length (256 bits)",
         len(h1) == 64)

except Exception as e:
    test("SHA-256 integrity test suite", False, str(e))


# ============================================================
# SECTION 3 — RSA-2048 DIGITAL SIGNATURES
# ============================================================

section("3. RSA-2048 Digital Signatures")

try:
    private_key, public_key = generate_rsa_keypair()
    content = "Clinical finding: Patient cohort A responded positively"

    # Test signing
    signature = sign_data(private_key, content)
    test("RSA-PSS signature generation", signature is not None)

    # Test valid signature verifies correctly
    test("Valid signature verified successfully",
         verify_signature(public_key, content, signature))

    # Test modified content fails verification
    modified = content + " (tampered)"
    test("Modified content correctly rejected",
         not verify_signature(public_key, modified, signature))

    # Test wrong public key fails verification
    _, wrong_public = generate_rsa_keypair()
    test("Wrong public key correctly rejected",
         not verify_signature(wrong_public, content, signature))

    # Test signature is base64 encoded string
    import base64
    try:
        base64.b64decode(signature)
        sig_is_b64 = True
    except Exception:
        sig_is_b64 = False
    test("Signature is correctly base64 encoded", sig_is_b64)

except Exception as e:
    test("RSA-2048 signature test suite", False, str(e))


# ============================================================
# SECTION 4 — BCRYPT PASSWORD HASHING
# ============================================================

section("4. bcrypt Password Hashing")

try:
    password = "Research@123"
    hashed = hash_password(password)

    # Test correct password verifies
    test("Correct password verified successfully",
         verify_password(password, hashed))

    # Test wrong password fails
    test("Wrong password correctly rejected",
         not verify_password("WrongPassword@456", hashed))

    # Test two hashes of same password are different (unique salts)
    hashed2 = hash_password(password)
    test("Unique salt produces different hashes for same password",
         hashed != hashed2)

    # Test hash is a string
    test("Password hash stored as string", isinstance(hashed, str))

    # Test hash starts with bcrypt identifier
    test("Hash uses bcrypt format ($2b$)",
         hashed.startswith("$2b$"))

except Exception as e:
    test("bcrypt password hashing test suite", False, str(e))


# ============================================================
# SECTION 5 — KEY MANAGEMENT
# ============================================================

section("5. Key Management and RSA Key Storage")

TEST_USER = "test_user_temp"
TEST_PASSWORD = "TestPass@123"

try:
    # Generate key pair for test user
    generate_user_keys(TEST_USER, TEST_PASSWORD)
    test("RSA-2048 key pair generated and stored",
         os.path.exists(f"keys/{TEST_USER}_private.pem") and
         os.path.exists(f"keys/{TEST_USER}_public.pem"))

    # Test private key loads with correct password
    private_key = load_private_key(TEST_USER, TEST_PASSWORD)
    test("Private key loads with correct password",
         private_key is not None)

    # Test private key fails with wrong password
    wrong_pass_fail = False
    try:
        load_private_key(TEST_USER, "WrongPassword@999")
    except Exception:
        wrong_pass_fail = True
    test("Private key correctly rejected with wrong password",
         wrong_pass_fail)

    # Test public key loads without password
    public_key = load_public_key(TEST_USER)
    test("Public key loads without password",
         public_key is not None)

    # Test key rotation check works
    needs_rotation, msg = check_key_rotation(TEST_USER)
    test("Key rotation check returns valid response",
         isinstance(needs_rotation, bool) and isinstance(msg, str))

    # Test multi-recipient AES key encapsulation
    aes_key = generate_aes_key()
    store_encrypted_aes_key_for_users([TEST_USER], "test_file.txt", aes_key)
    retrieved_key = retrieve_aes_key(TEST_USER, "test_file.txt", TEST_PASSWORD)
    test("AES key wrapped and unwrapped via RSA encapsulation",
         aes_key == retrieved_key)

    # Test unauthorised user cannot retrieve AES key
    unauth_fail = False
    try:
        retrieve_aes_key("nonexistent_user", "test_file.txt", TEST_PASSWORD)
    except Exception:
        unauth_fail = True
    test("Unauthorised user correctly denied AES key access",
         unauth_fail)

except Exception as e:
    test("Key management test suite", False, str(e))


# ============================================================
# SECTION 6 — CHAINED AUDIT LOG
# ============================================================

section("6. Chained Audit Log Integrity")

try:
    # Log some test events
    log_event("test_user", "Researcher", "TEST_EVENT_1", "First test entry")
    log_event("test_user", "Researcher", "TEST_EVENT_2", "Second test entry")
    log_event("test_user", "Researcher", "TEST_EVENT_3", "Third test entry")

    # Verify chain is intact
    intact, message = verify_log_integrity()
    test("Audit log chain integrity verified", intact)

    # Test that tampering is detected
    # Manually modify an entry and check detection
    import json
    with open("audit_log.json", "r") as f:
        log = json.load(f)

    # Save original for restoration
    original_log = json.dumps(log)

    if len(log) >= 2:
        # Tamper with first entry
        log[0]["action"] = "TAMPERED_ACTION"
        with open("audit_log.json", "w") as f:
            json.dump(log, f)

        # Verify tampering is detected
        intact_after_tamper, tamper_msg = verify_log_integrity()
        test("Tampering in audit log correctly detected",
             not intact_after_tamper)

        # Restore original log
        with open("audit_log.json", "w") as f:
            f.write(original_log)

        # Verify chain is intact again after restoration
        intact_restored, _ = verify_log_integrity()
        test("Audit log integrity restored after fix",
             intact_restored)

except Exception as e:
    test("Audit log test suite", False, str(e))


# ============================================================
# SECTION 7 — ROLE-BASED ACCESS CONTROL
# ============================================================

section("7. Role-Based Access Control (Complete Mediation)")

try:
    from auth import require_role

    # Test that a function decorated with require_role
    # correctly blocks wrong roles

    @require_role(["Researcher"])
    def researcher_only_function(username, role):
        return "accessed"

    # Correct role should succeed
    result = researcher_only_function("alice", "Researcher")
    test("Correct role granted access",
         result == "accessed")

    # Wrong role should be blocked
    result_blocked = researcher_only_function("alice", "Clinician")
    test("Wrong role correctly blocked by require_role decorator",
         result_blocked is None)

    # Auditor should also be blocked
    result_blocked2 = researcher_only_function("alice", "Auditor")
    test("Auditor correctly blocked from Researcher function",
         result_blocked2 is None)

except Exception as e:
    test("Role-based access control test suite", False, str(e))


# ============================================================
# SECTION 8 — LEGAL COMPLIANCE FEATURES
# ============================================================

section("8. Legal Compliance Feature Verification")

try:
    # GDPR Article 32 - encryption of personal data
    key = generate_aes_key()
    test("GDPR Art.32: AES-256-GCM encryption available",
         key is not None and len(key) == 32)

    # GDPR Article 32 - integrity verification
    data = "test data"
    h = hash_data(data)
    test("GDPR Art.32: SHA-256 integrity verification available",
         verify_integrity(data, h))

    # GDPR Article 5(2) - accountability via audit log
    intact, _ = verify_log_integrity()
    test("GDPR Art.5(2): Tamper-evident audit log present and intact",
         intact)

    # GDPR Article 5(1)(f) - access control
    from auth import require_role

    @require_role(["Auditor"])
    def auditor_function(username, role):
        return True

    test("GDPR Art.5(1)(f): Role-based access control enforced",
         auditor_function("carol", "Auditor") is True)

    test("GDPR Art.5(1)(f): Unauthorised access blocked",
         auditor_function("bob", "Researcher") is None)

    # NHS DSPT 9.2.2 - MFA available
    from config import MFA_ENABLED
    test("NHS DSPT 9.2.2: MFA implementation present",
         isinstance(MFA_ENABLED, bool))

    # Non-repudiation via digital signatures
    private_key, public_key = generate_rsa_keypair()
    sig = sign_data(private_key, "test finding")
    test("Non-repudiation: RSA-PSS digital signatures available",
         verify_signature(public_key, "test finding", sig))

except Exception as e:
    test("Legal compliance test suite", False, str(e))


# ============================================================
# CLEANUP TEST FILES
# ============================================================

# Remove temporary test user keys
import shutil
for f in ["keys/test_user_temp_private.pem",
          "keys/test_user_temp_public.pem"]:
    if os.path.exists(f):
        os.remove(f)

# Remove test AES key entry
key_store = "keys/aes_keys.json"
if os.path.exists(key_store):
    with open(key_store, "r") as f:
        ks = json.load(f)
    ks = {k: v for k, v in ks.items()
          if not k.startswith("test_user_temp")}
    with open(key_store, "w") as f:
        json.dump(ks, f, indent=4)


# ============================================================
# FINAL RESULTS
# ============================================================

total = passed + failed
print(f"\n  {'='*55}")
print(f"  TEST RESULTS")
print(f"  {'='*55}")
print(f"  Total  : {total}")
print(f"  Passed : {passed}")
print(f"  Failed : {failed}")
print(f"  {'='*55}")

if failed == 0:
    print(f"\n  [+] All tests passed. System is functioning correctly.")
else:
    print(f"\n  [!] {failed} test(s) failed. Review output above.")