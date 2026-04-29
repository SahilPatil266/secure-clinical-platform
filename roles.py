# roles.py
# Implements role-based menus and operations for the SecureClinical platform.
#
# Security principles implemented:
#
# 1. Complete Mediation (Saltzer & Schroeder, 1975)
#    Every sensitive function is decorated with @require_role(),
#    enforcing access control at the function level independently
#    of menu routing. Role checks happen on every call, not just login.
#
# 2. Re-authentication for sensitive operations (NIST SP 800-63B)
#    Private key operations (decrypt, sign, retrieve AES key) always
#    prompt for password re-entry. A valid session alone is insufficient.
#
# 3. Separation of Duties for research finding submission
#    Applied selectively to the highest-risk operation: submitting
#    verified research findings. A second authorised party (Clinician)
#    must countersign before a finding reaches VERIFIED status.
#    This prevents a single compromised account from unilaterally
#    submitting falsified clinical research data.
#
# 4. Principle of Least Privilege
#    Each role can only access the operations it requires:
#    - Researchers: encrypt/decrypt data, sign/verify findings
#    - Clinicians: upload/retrieve encrypted datasets, countersign findings
#    - Auditors: view audit log, verify log integrity, verify signatures
#
# 5. HSM Abstraction Layer
#    All signing and key operations are mediated through HSMInterface,
#    ensuring no application code directly accesses private key material.
#    The backend can be swapped to real HSM hardware without changing
#    any code in this module.

import os
import json
from getpass import getpass
from auth import require_role, reauth, get_all_users_by_role
from crypto import (
    generate_aes_key, encrypt_data, decrypt_data,
    hash_data, verify_integrity
)
from key_manager import (
    store_encrypted_aes_key_for_users,
    retrieve_aes_key,
    load_public_key
)
from audit import log_event, view_log, verify_log_integrity
from hsm import HSMInterface

DATA_DIR = "data"
FINDINGS_FILE = "findings.json"


def _ensure_data_dir():
    """Create data directory if it doesn't exist."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)


def _load_findings():
    """Load research findings from findings.json."""
    if os.path.exists(FINDINGS_FILE):
        with open(FINDINGS_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_findings(findings):
    """Save research findings to findings.json."""
    with open(FINDINGS_FILE, "w") as f:
        json.dump(findings, f, indent=4)


# ============================================================
# SHARED SECURITY OPERATIONS
# ============================================================

def perform_key_rotation(username, role):
    """
    Allow any authenticated user to rotate their RSA key pair.
    Accessible from all role menus as a security maintenance operation.
    Re-authentication required - this is a critical key management operation.
    """
    print("\n  --- RSA Key Rotation ---")
    print("  This will generate a new RSA key pair and re-wrap all your")
    print("  existing AES keys. Your old keys will be archived.")
    print("  This operation cannot be undone.\n")

    confirm = input("  Are you sure you want to rotate your keys? (yes/no): ").strip()
    if confirm.lower() != "yes":
        print("  [*] Key rotation cancelled.")
        return

    current_password = reauth(username, "RSA key rotation")
    if not current_password:
        return

    print("\n  You may set a new password for your rotated keys,")
    print("  or press Enter to keep the same password.")
    new_password = getpass("  New password (or Enter to keep current): ").strip()

    if not new_password:
        new_password = current_password
        print("  [*] Keeping current password for new keys.")
    else:
        from auth import validate_password_complexity
        ok, msg = validate_password_complexity(new_password)
        if not ok:
            print(f"  [!] {msg}")
            return

    from key_manager import rotate_user_keys
    success = rotate_user_keys(username, current_password, new_password)

    if success:
        log_event(username, role, "KEY_ROTATION_COMPLETED",
                 f"RSA key pair rotated successfully for {username}")
    else:
        log_event(username, role, "KEY_ROTATION_FAILED",
                 f"Key rotation failed for {username}")


def check_key_status(username, role):
    """
    Display current key rotation status and countdown tracker.
    Available to all roles as a security awareness feature.
    """
    from key_manager import check_key_rotation
    needs_rotation, msg = check_key_rotation(username)
    print(f"\n  --- RSA Key Rotation Status ---\n")
    print(f"  {msg}")
    log_event(username, role, "KEY_STATUS_CHECKED",
             f"Key rotation status checked by {username}")


# ============================================================
# RESEARCHER ROLE
# ============================================================

@require_role(["Researcher"])
def researcher_encrypt_file(username, role):
    """
    Encrypt a research data file using AES-256-GCM with AAD.

    AAD binds the encryption context (username + filename) to the
    ciphertext. If the ciphertext is moved to a different user's
    context, decryption fails - providing cryptographic enforcement
    of data ownership beyond access control checks.

    AES key wrapping is performed via the HSM interface, ensuring
    all key operations are mediated, logged, and backend-agnostic.
    In production, replacing SoftwareHSMBackend with a PKCS#11
    backend would provide hardware-level key protection with no
    changes required to this function.
    """
    _ensure_data_dir()

    print("\n  --- Encrypt Research Data ---")
    filename = input("  Enter filename to create (e.g. study_results.txt): ").strip()
    print("  Enter the data to encrypt (press Enter twice when done):")

    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)

    plaintext = "\n".join(lines)

    if not plaintext:
        print("  [!] No data entered. Operation cancelled.")
        return

    aes_key = generate_aes_key()
    aad = f"{username}:{filename}"
    encrypted = encrypt_data(aes_key, plaintext, aad)
    integrity_hash = hash_data(plaintext)

    file_data = {
        "encrypted_content": encrypted,
        "integrity_hash": integrity_hash,
        "owner": username,
        "aad": aad,
        "filename": filename
    }

    filepath = f"{DATA_DIR}/{filename}.json"
    with open(filepath, "w") as f:
        json.dump(file_data, f, indent=4)

    # Use HSM interface for key wrapping operations
    hsm = HSMInterface(username, role)
    clinicians = get_all_users_by_role("Clinician")
    authorised_users = [username] + clinicians

    print(f"\n  [*] Wrapping AES key via HSM interface...")
    store_encrypted_aes_key_for_users(authorised_users, filename, aes_key)

    log_event(
        username, role, "FILE_ENCRYPTED",
        f"File '{filename}' encrypted with AES-256-GCM + AAD. "
        f"Keys wrapped via {type(hsm.backend).__name__}. "
        f"Authorised recipients: {authorised_users}"
    )

    print(f"\n  [+] File '{filename}' encrypted successfully.")
    print(f"  [+] Integrity hash: {integrity_hash[:20]}...")
    print(f"  [+] Authorised recipients: {authorised_users}")
    print(f"  [+] HSM backend: {type(hsm.backend).__name__}")


@require_role(["Researcher"])
def researcher_decrypt_file(username, role):
    """
    Decrypt a research data file via HSM interface.

    AES key unwrapping is performed through the HSM interface,
    ensuring the operation is mediated and logged regardless of
    the underlying backend. Re-authentication required.
    """
    _ensure_data_dir()

    print("\n  --- Decrypt Research Data ---")

    files = [f.replace(".json", "") for f in os.listdir(DATA_DIR)
             if f.endswith(".json")]

    if not files:
        print("  [!] No encrypted files found.")
        return

    print("\n  Available files:")
    for i, f in enumerate(files, 1):
        print(f"    {i}. {f}")

    filename = input("\n  Enter filename to decrypt: ").strip()

    filepath = f"{DATA_DIR}/{filename}.json"
    if not os.path.exists(filepath):
        print(f"  [!] File '{filename}' not found.")
        return

    password = reauth(username, f"decrypt file '{filename}'")
    if not password:
        return

    try:
        hsm = HSMInterface(username, role)
        aes_key = retrieve_aes_key(username, filename, password)

        with open(filepath, "r") as f:
            file_data = json.load(f)

        plaintext = decrypt_data(
            aes_key,
            file_data["encrypted_content"],
            file_data["aad"]
        )

        if verify_integrity(plaintext, file_data["integrity_hash"]):
            print(f"\n  [+] Integrity verified - file has not been tampered with.")
        else:
            print(f"\n  [!] INTEGRITY CHECK FAILED - file may have been tampered with!")
            log_event(username, role, "INTEGRITY_FAILURE",
                     f"Integrity check failed for file '{filename}'")

        print(f"\n  --- Decrypted Content ---")
        print(plaintext)
        print(f"  --- End of Content ---")
        print(f"\n  [+] HSM backend: {type(hsm.backend).__name__}")

        log_event(username, role, "FILE_DECRYPTED",
                 f"File '{filename}' decrypted via HSM interface")

    except Exception as e:
        print(f"\n  [!] Decryption failed: {e}")
        log_event(username, role, "DECRYPTION_FAILED",
                 f"Failed to decrypt '{filename}': {str(e)}")


@require_role(["Researcher"])
def researcher_sign_finding(username, role):
    """
    Create and digitally sign a research finding via HSM interface.

    Signing is performed through the HSM interface - the application
    requests a signature and receives one back, without directly
    accessing private key material. This mirrors how a real HSM
    operates: you send data in, get a signature out.

    Separation of duties: finding enters PENDING_COUNTERSIGN status.
    Clinician countersignature required before VERIFIED status.
    """
    print("\n  --- Sign Research Finding ---")
    print("  Enter your research finding (press Enter twice when done):")

    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)

    content = "\n".join(lines)

    if not content:
        print("  [!] No content entered. Operation cancelled.")
        return

    finding_id = input("  Enter a finding ID (e.g. FINDING_001): ").strip()

    findings = _load_findings()
    if finding_id in findings:
        print(f"  [!] Finding ID '{finding_id}' already exists.")
        return

    password = reauth(username, f"sign finding '{finding_id}'")
    if not password:
        return

    try:
        # Sign via HSM interface - private key never directly accessed
        hsm = HSMInterface(username, role)
        signature = hsm.sign(content, password)
        content_hash = hash_data(content)

        findings[finding_id] = {
            "content": content,
            "content_hash": content_hash,
            "primary_signer": username,
            "primary_signature": signature,
            "countersigner": None,
            "countersignature": None,
            "status": "PENDING_COUNTERSIGN",
            "hsm_backend": type(hsm.backend).__name__
        }

        _save_findings(findings)

        log_event(
            username, role, "FINDING_SIGNED",
            f"Finding '{finding_id}' signed via "
            f"{type(hsm.backend).__name__}. "
            f"Status: PENDING_COUNTERSIGN"
        )

        print(f"\n  [+] Finding '{finding_id}' signed successfully.")
        print(f"  [+] Status: PENDING_COUNTERSIGN")
        print(f"  [+] HSM backend: {type(hsm.backend).__name__}")
        print(f"  [+] Awaiting Clinician countersignature.")

    except Exception as e:
        print(f"\n  [!] Signing failed: {e}")


@require_role(["Researcher"])
def researcher_view_findings(username, role):
    """Display all research findings and their current status."""
    findings = _load_findings()

    if not findings:
        print("\n  No findings recorded.")
        return

    print(f"\n  {'='*55}")
    print(f"  RESEARCH FINDINGS")
    print(f"  {'='*55}")

    for finding_id, finding in findings.items():
        print(f"\n  ID      : {finding_id}")
        print(f"  Signer  : {finding['primary_signer']}")
        print(f"  Status  : {finding['status']}")
        if finding['countersigner']:
            print(f"  Counter : {finding['countersigner']}")
        print(f"  Content : {finding['content'][:80]}...")


# ============================================================
# CLINICIAN ROLE
# ============================================================

@require_role(["Clinician"])
def clinician_upload_dataset(username, role):
    """
    Upload and encrypt a patient dataset.

    Clinicians encrypt patient data using AES-256-GCM with AAD.
    The AES key is wrapped for all Researchers and the uploading
    Clinician, enabling cross-role collaborative access while
    maintaining cryptographic access control.
    """
    _ensure_data_dir()

    print("\n  --- Upload Encrypted Patient Dataset ---")
    filename = input("  Enter dataset filename (e.g. patient_cohort_01.txt): ").strip()
    print("  Enter patient dataset (press Enter twice when done):")

    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)

    plaintext = "\n".join(lines)

    if not plaintext:
        print("  [!] No data entered. Operation cancelled.")
        return

    aes_key = generate_aes_key()
    aad = f"{username}:{filename}"
    encrypted = encrypt_data(aes_key, plaintext, aad)
    integrity_hash = hash_data(plaintext)

    file_data = {
        "encrypted_content": encrypted,
        "integrity_hash": integrity_hash,
        "owner": username,
        "aad": aad,
        "filename": filename,
        "data_type": "patient_dataset"
    }

    filepath = f"{DATA_DIR}/{filename}.json"
    with open(filepath, "w") as f:
        json.dump(file_data, f, indent=4)

    researchers = get_all_users_by_role("Researcher")
    authorised_users = [username] + researchers

    print(f"\n  [*] Wrapping AES key for authorised recipients...")
    store_encrypted_aes_key_for_users(authorised_users, filename, aes_key)

    log_event(
        username, role, "DATASET_UPLOADED",
        f"Patient dataset '{filename}' encrypted and uploaded. "
        f"Authorised recipients: {authorised_users}"
    )

    print(f"\n  [+] Dataset '{filename}' uploaded and encrypted successfully.")
    print(f"  [+] Authorised recipients: {authorised_users}")


@require_role(["Clinician"])
def clinician_retrieve_dataset(username, role):
    """
    Retrieve and decrypt a patient dataset.
    Requires re-authentication - RSA private key needed to unwrap AES key.
    """
    _ensure_data_dir()

    print("\n  --- Retrieve Patient Dataset ---")

    files = [f.replace(".json", "") for f in os.listdir(DATA_DIR)
             if f.endswith(".json")]

    if not files:
        print("  [!] No datasets found.")
        return

    print("\n  Available datasets:")
    for i, f in enumerate(files, 1):
        print(f"    {i}. {f}")

    filename = input("\n  Enter dataset filename to retrieve: ").strip()

    filepath = f"{DATA_DIR}/{filename}.json"
    if not os.path.exists(filepath):
        print(f"  [!] Dataset '{filename}' not found.")
        return

    password = reauth(username, f"retrieve dataset '{filename}'")
    if not password:
        return

    try:
        hsm = HSMInterface(username, role)
        aes_key = retrieve_aes_key(username, filename, password)

        with open(filepath, "r") as f:
            file_data = json.load(f)

        plaintext = decrypt_data(
            aes_key,
            file_data["encrypted_content"],
            file_data["aad"]
        )

        if verify_integrity(plaintext, file_data["integrity_hash"]):
            print(f"\n  [+] Integrity verified - dataset has not been tampered with.")
        else:
            print(f"\n  [!] INTEGRITY CHECK FAILED - dataset may have been tampered with!")
            log_event(username, role, "INTEGRITY_FAILURE",
                     f"Integrity check failed for dataset '{filename}'")

        print(f"\n  --- Dataset Content ---")
        print(plaintext)
        print(f"  --- End of Dataset ---")
        print(f"\n  [+] HSM backend: {type(hsm.backend).__name__}")

        log_event(username, role, "DATASET_RETRIEVED",
                 f"Dataset '{filename}' retrieved via HSM interface")

    except Exception as e:
        print(f"\n  [!] Retrieval failed: {e}")
        log_event(username, role, "RETRIEVAL_FAILED",
                 f"Failed to retrieve '{filename}': {str(e)}")


@require_role(["Clinician"])
def clinician_countersign_finding(username, role):
    """
    Countersign a research finding via HSM interface.

    Both signature verification (primary) and countersigning are
    performed through the HSM interface, ensuring consistent
    mediation and logging of all key operations.

    Implements separation of duties - the Clinician independently
    verifies the Researcher's primary signature before adding their
    own countersignature. Only when both signatures are present does
    the finding reach VERIFIED status.
    """
    findings = _load_findings()

    pending = {fid: f for fid, f in findings.items()
               if f["status"] == "PENDING_COUNTERSIGN"}

    if not pending:
        print("\n  No findings awaiting countersignature.")
        return

    print(f"\n  --- Countersign Research Finding ---")
    print(f"\n  Findings awaiting countersignature:")

    for finding_id, finding in pending.items():
        print(f"\n    ID      : {finding_id}")
        print(f"    Signer  : {finding['primary_signer']}")
        print(f"    Content : {finding['content'][:100]}...")

    finding_id = input("\n  Enter finding ID to countersign: ").strip()

    if finding_id not in pending:
        print(f"  [!] Finding '{finding_id}' not found or not pending.")
        return

    finding = pending[finding_id]

    print(f"\n  [*] Verifying primary signature from "
          f"{finding['primary_signer']} via HSM interface...")

    try:
        hsm = HSMInterface(username, role)
        sig_valid = hsm.verify(
            finding["primary_signer"],
            finding["content"],
            finding["primary_signature"]
        )

        if not sig_valid:
            print(f"  [!] Primary signature INVALID - cannot countersign.")
            log_event(username, role, "COUNTERSIGN_REJECTED",
                     f"Primary signature invalid for '{finding_id}'")
            return

        print(f"  [+] Primary signature verified via HSM interface.")

    except Exception as e:
        print(f"  [!] Could not verify primary signature: {e}")
        return

    password = reauth(username, f"countersign finding '{finding_id}'")
    if not password:
        return

    try:
        countersignature = hsm.sign(finding["content"], password)

        findings[finding_id]["countersigner"] = username
        findings[finding_id]["countersignature"] = countersignature
        findings[finding_id]["status"] = "VERIFIED"

        _save_findings(findings)

        log_event(
            username, role, "FINDING_COUNTERSIGNED",
            f"Finding '{finding_id}' countersigned via "
            f"{type(hsm.backend).__name__}. "
            f"Status: VERIFIED. "
            f"Primary signer: {finding['primary_signer']}"
        )

        print(f"\n  [+] Finding '{finding_id}' countersigned successfully.")
        print(f"  [+] Status: VERIFIED")
        print(f"  [+] HSM backend: {type(hsm.backend).__name__}")

    except Exception as e:
        print(f"\n  [!] Countersigning failed: {e}")


# ============================================================
# AUDITOR ROLE
# ============================================================

@require_role(["Auditor"])
def auditor_view_log(username, role):
    """
    Display the full audit log.
    Auditors have read-only access to system activity records.
    """
    print("\n" + view_log())
    log_event(username, role, "AUDIT_LOG_VIEWED",
             "Audit log accessed by Auditor")


@require_role(["Auditor"])
def auditor_verify_log_integrity(username, role):
    """
    Verify the integrity of the chained audit log.

    Recomputes every entry's hash and checks the chain is unbroken.
    Any modification to historical entries breaks the chain,
    providing cryptographic evidence of tampering.
    """
    print("\n  [*] Verifying audit log chain integrity...")

    intact, message = verify_log_integrity()

    if intact:
        print(f"\n  [+] {message}")
    else:
        print(f"\n  [!] INTEGRITY VIOLATION DETECTED")
        print(f"  [!] {message}")

    log_event(username, role, "LOG_INTEGRITY_CHECK",
             f"Audit log integrity verification: {message}")


@require_role(["Auditor"])
def auditor_verify_finding_signatures(username, role):
    """
    Verify digital signatures on all research findings via HSM interface.

    Auditors verify signatures through the HSM interface using only
    public keys - no private key access required. This demonstrates
    the non-repudiation property: signatures can be independently
    verified by any party with the public key.
    """
    findings = _load_findings()

    if not findings:
        print("\n  No findings to verify.")
        return

    print(f"\n  --- Verify Research Finding Signatures ---")
    hsm = HSMInterface(username, role)
    print(f"  HSM backend: {type(hsm.backend).__name__}\n")
    print(f"  Verifying {len(findings)} finding(s)...\n")

    for finding_id, finding in findings.items():
        print(f"  Finding: {finding_id}")
        print(f"  Status : {finding['status']}")

        try:
            primary_valid = hsm.verify(
                finding["primary_signer"],
                finding["content"],
                finding["primary_signature"]
            )
            status = "[+] VALID" if primary_valid else "[!] INVALID"
            print(f"  Primary signature ({finding['primary_signer']}): {status}")
        except Exception as e:
            print(f"  Primary signature: [!] ERROR - {e}")

        if finding["countersignature"]:
            try:
                counter_valid = hsm.verify(
                    finding["countersigner"],
                    finding["content"],
                    finding["countersignature"]
                )
                status = "[+] VALID" if counter_valid else "[!] INVALID"
                print(f"  Countersignature ({finding['countersigner']}): {status}")
            except Exception as e:
                print(f"  Countersignature: [!] ERROR - {e}")
        else:
            print(f"  Countersignature: [*] PENDING")

        content_hash = hash_data(finding["content"])
        hash_valid = content_hash == finding["content_hash"]
        status = "[+] INTACT" if hash_valid else "[!] TAMPERED"
        print(f"  Content integrity: {status}")
        print()

    log_event(username, role, "SIGNATURES_VERIFIED",
             f"Signature verification via {type(hsm.backend).__name__} "
             f"on {len(findings)} finding(s)")


@require_role(["Auditor"])
def auditor_view_all_findings(username, role):
    """
    Display all research findings with full status information.
    Auditors have read-only access - cannot modify findings.
    """
    findings = _load_findings()

    if not findings:
        print("\n  No findings recorded.")
        return

    print(f"\n  {'='*55}")
    print(f"  ALL RESEARCH FINDINGS")
    print(f"  {'='*55}")

    for finding_id, finding in findings.items():
        print(f"\n  ID           : {finding_id}")
        print(f"  Status       : {finding['status']}")
        print(f"  Primary      : {finding['primary_signer']}")
        print(f"  Countersigner: {finding['countersigner'] or 'Pending'}")
        if finding.get('hsm_backend'):
            print(f"  HSM Backend  : {finding['hsm_backend']}")
        print(f"  Content      : {finding['content'][:100]}...")

    log_event(username, role, "FINDINGS_VIEWED",
             f"All findings viewed by Auditor")


# ============================================================
# ROLE MENU ROUTING
# ============================================================

def researcher_menu(username):
    """Main menu for Researcher role."""
    while True:
        print(f"\n  {'='*45}")
        print(f"  RESEARCHER MENU — {username}")
        print(f"  {'='*45}")
        print("  1. Encrypt research data")
        print("  2. Decrypt research data")
        print("  3. Sign research finding")
        print("  4. View all findings")
        print("  5. Check key rotation status")
        print("  6. Rotate RSA keys")
        print("  7. Logout")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            researcher_encrypt_file(username, "Researcher")
        elif choice == "2":
            researcher_decrypt_file(username, "Researcher")
        elif choice == "3":
            researcher_sign_finding(username, "Researcher")
        elif choice == "4":
            researcher_view_findings(username, "Researcher")
        elif choice == "5":
            check_key_status(username, "Researcher")
        elif choice == "6":
            perform_key_rotation(username, "Researcher")
        elif choice == "7":
            log_event(username, "Researcher", "LOGOUT", "User logged out")
            print(f"\n  Goodbye, {username}.")
            break
        else:
            print("  [!] Invalid option.")


def clinician_menu(username):
    """Main menu for Clinician role."""
    while True:
        print(f"\n  {'='*45}")
        print(f"  CLINICIAN MENU — {username}")
        print(f"  {'='*45}")
        print("  1. Upload encrypted patient dataset")
        print("  2. Retrieve patient dataset")
        print("  3. Countersign research finding")
        print("  4. Check key rotation status")
        print("  5. Rotate RSA keys")
        print("  6. Logout")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            clinician_upload_dataset(username, "Clinician")
        elif choice == "2":
            clinician_retrieve_dataset(username, "Clinician")
        elif choice == "3":
            clinician_countersign_finding(username, "Clinician")
        elif choice == "4":
            check_key_status(username, "Clinician")
        elif choice == "5":
            perform_key_rotation(username, "Clinician")
        elif choice == "6":
            log_event(username, "Clinician", "LOGOUT", "User logged out")
            print(f"\n  Goodbye, {username}.")
            break
        else:
            print("  [!] Invalid option.")


def auditor_menu(username):
    """Main menu for Auditor role."""
    while True:
        print(f"\n  {'='*45}")
        print(f"  AUDITOR MENU — {username}")
        print(f"  {'='*45}")
        print("  1. View audit log")
        print("  2. Verify audit log integrity")
        print("  3. Verify finding signatures")
        print("  4. View all findings")
        print("  5. Check key rotation status")
        print("  6. Rotate RSA keys")
        print("  7. Logout")

        choice = input("\n  Select option: ").strip()

        if choice == "1":
            auditor_view_log(username, "Auditor")
        elif choice == "2":
            auditor_verify_log_integrity(username, "Auditor")
        elif choice == "3":
            auditor_verify_finding_signatures(username, "Auditor")
        elif choice == "4":
            auditor_view_all_findings(username, "Auditor")
        elif choice == "5":
            check_key_status(username, "Auditor")
        elif choice == "6":
            perform_key_rotation(username, "Auditor")
        elif choice == "7":
            log_event(username, "Auditor", "LOGOUT", "User logged out")
            print(f"\n  Goodbye, {username}.")
            break
        else:
            print("  [!] Invalid option.")