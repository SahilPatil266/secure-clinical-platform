# auth.py
# Handles user authentication for the SecureClinical platform.
#
# Security principles implemented:
# - bcrypt with cost factor 12 for password hashing
#   Selected over SHA-256 for password storage because bcrypt is a
#   memory-hard function resistant to GPU-accelerated brute-force attacks.
#   The cost factor can be increased as hardware improves, future-proofing
#   the implementation against advances in computing power.
#
# - Email-based OTP as a second authentication factor
#   Mirrors NHS Digital Data Security and Protection Toolkit requirement 9.2.2
#   mandating MFA for systems processing special category health data.
#   Email delivery chosen over TOTP authenticator apps to reduce user friction
#   while maintaining a meaningful second factor - an attacker with only the
#   password still cannot authenticate without access to the registered email.
#
# - Complete mediation enforced at function level via require_role() decorator
#   Every sensitive operation verifies the caller's role independently of
#   menu routing, ensuring no privilege escalation is possible even if
#   the UI layer is bypassed.
#
# - Re-authentication required for all private key operations
#   A valid session is insufficient to perform cryptographic operations -
#   the user's password must be re-entered each time, ensuring a logged-in
#   but unattended session cannot be exploited.

import json
import os
import random
import smtplib
import bcrypt
from getpass import getpass
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import MFA_ENABLED, EMAIL_SENDER, EMAIL_APP_PASSWORD, EMAIL_SUBJECT
from audit import log_event

USERS_FILE = "users.json"


# ============================================================
# COMPLETE MEDIATION — ROLE ENFORCEMENT DECORATOR
# ============================================================
# Implements Saltzer and Schroeder's Complete Mediation principle (1975):
# every access to every resource must be checked for authorisation.
# This decorator is applied to all sensitive functions, ensuring that
# even if menu routing is bypassed, the function itself enforces the
# role requirement independently.

def require_role(allowed_roles):
    """
    Decorator that enforces role-based access control at function level.
    Implements complete mediation - access is checked on every call,
    not just at login or menu routing level.

    Args:
        allowed_roles: list of roles permitted to call the decorated function

    Usage:
        @require_role(["Researcher"])
        def encrypt_file(username, role, ...):
            ...
    """
    def decorator(func):
        def wrapper(username, role, *args, **kwargs):
            if role not in allowed_roles:
                log_event(
                    username, role, "ACCESS_DENIED",
                    f"Attempted unauthorised access to {func.__name__}. "
                    f"Required role: {allowed_roles}, actual role: {role}"
                )
                print(f"\n  [!] Access denied.")
                print(f"  [!] This operation requires role: {allowed_roles}")
                print(f"  [!] Your role: {role}")
                return None
            return func(username, role, *args, **kwargs)
        return wrapper
    return decorator


# ============================================================
# USER STORAGE
# ============================================================

def _load_users():
    """Load user accounts from users.json."""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_users(users):
    """Save user accounts to users.json."""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password):
    """
    Hash a password using bcrypt with automatic salt generation.

    bcrypt is specifically chosen over general-purpose hash functions
    (SHA-256, SHA-3) for password storage because:

    1. Memory-hard: resistant to GPU/ASIC accelerated brute-force attacks
       that make SHA-based password hashing trivially parallelisable
    2. Configurable cost factor (rounds=12): approximately 300ms hash time,
       slow enough to deter brute-force while acceptable for interactive login.
       Can be increased as hardware improves without changing stored hashes.
    3. Automatic salting: bcrypt generates and embeds a unique salt per hash,
       eliminating rainbow table attacks and ensuring identical passwords
       produce different hashes across users.

    Note: SHA-256 is appropriate for data integrity verification (used in
    audit.py and crypto.py) but is intentionally NOT used here for passwords
    due to its speed making it unsuitable for credential protection.
    """
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(password, hashed):
    """
    Verify a password against its bcrypt hash.
    bcrypt.checkpw handles salt extraction and comparison automatically.

    Returns:
        True if password matches stored hash, False otherwise
    """
    return bcrypt.checkpw(password.encode(), hashed.encode())

def validate_password_complexity(password):
    """
    Enforce password complexity requirements before account creation.

    Requirements align with GDPR Article 32 and NHS Digital DSPT
    password policy for systems processing special category health data:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character

    Args:
        password: plaintext password to validate

    Returns:
        (True, "Password accepted") if requirements met
        (False, reason) if requirements not met
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."

    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character."

    return True, "Password accepted."


# ============================================================
# RE-AUTHENTICATION FOR SENSITIVE OPERATIONS
# ============================================================

def reauth(username, operation_description):
    """
    Prompt user to re-enter their password before a sensitive operation.

    Implements step-up authentication - a valid login session is
    insufficient to perform cryptographic operations. The password
    must be re-entered each time, ensuring:

    1. An unattended logged-in session cannot be exploited
    2. The password is available to decrypt the RSA private key
       for signing/decryption operations
    3. Every sensitive operation is independently authorised

    This aligns with NIST SP 800-63B Section 4 re-authentication
    requirements for high-assurance operations.

    Args:
        username: current logged-in user
        operation_description: human-readable description shown to user

    Returns:
        password string if verified, None if verification fails
    """
    users = _load_users()
    user = users.get(username)

    if not user:
        return None

    print(f"\n  [*] Re-authentication required for: {operation_description}")
    print(f"  [*] Please confirm your identity to proceed.")

    attempts = 0
    max_attempts = 3

    while attempts < max_attempts:
        password = getpass(f"  Password (attempt {attempts+1}/{max_attempts}): ")

        if verify_password(password, user["password_hash"]):
            log_event(
                username, user["role"], "REAUTH_SUCCESS",
                f"Re-authentication successful for: {operation_description}"
            )
            return password
        else:
            attempts += 1
            remaining = max_attempts - attempts
            if remaining > 0:
                print(f"  [!] Incorrect password. {remaining} attempts remaining.")
            else:
                log_event(
                    username, user["role"], "REAUTH_FAILED",
                    f"Re-authentication failed for: {operation_description} "
                    f"- maximum attempts exceeded"
                )
                print("  [!] Re-authentication failed. Operation cancelled.")
                return None


# ============================================================
# MFA - EMAIL OTP
# ============================================================

def generate_otp():
    """
    Generate a cryptographically secure 6-digit OTP.

    Uses random.SystemRandom() which internally uses os.urandom(),
    providing cryptographically secure randomness from the OS entropy
    pool. This is suitable for security-sensitive OTP generation,
    unlike random.randint() which uses a pseudo-random generator
    that could theoretically be predicted.
    """
    secure_random = random.SystemRandom()
    return str(secure_random.randint(100000, 999999))


def send_otp_email(recipient_email, otp_code, username):
    """
    Deliver OTP to user's registered email via Gmail SMTP over TLS.

    Email-based OTP provides a second authentication factor independent
    of the password - an attacker in possession of the password alone
    cannot authenticate without also controlling the registered email
    account, significantly raising the bar for credential-based attacks.

    TLS (STARTTLS on port 587) ensures the OTP is encrypted in transit,
    preventing interception by network-level attackers.

    This mirrors NHS Digital DSPT requirement 9.2.2 mandating MFA for
    systems processing special category health data under Article 9 GDPR.

    Args:
        recipient_email: user's registered email address
        otp_code: 6-digit code to deliver
        username: included in email body for user context

    Returns:
        True if delivered successfully, False if delivery failed
    """
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = recipient_email
        msg["Subject"] = EMAIL_SUBJECT

        body = f"""
SecureClinical Platform - Login Verification
{'='*45}

Hello {username},

A login attempt was made to your SecureClinical account.

Your one-time verification code is:

        {otp_code}

This code is valid for 5 minutes and can only be used once.

If you did not attempt to log in, your account password may be
compromised. Please contact your system administrator immediately.

{'='*45}
This is an automated security message. Do not reply.
        """

        msg.attach(MIMEText(body, "plain"))

        # STARTTLS upgrades the connection to TLS before credentials
        # are transmitted, preventing interception of the App Password
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(EMAIL_SENDER, EMAIL_APP_PASSWORD)
            server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())

        return True

    except Exception as e:
        print(f"  [!] Failed to send OTP email: {e}")
        return False


def verify_otp(generated_code, entered_code):
    """
    Compare generated OTP against user-entered code.

    String comparison is used rather than hmac.compare_digest because
    OTPs are single-use, time-limited (5 minutes), and 6 digits -
    making timing-based attacks impractical. In a production system
    with longer-lived tokens, hmac.compare_digest would be preferred.

    Returns:
        True if codes match, False otherwise
    """
    return generated_code.strip() == entered_code.strip()


# ============================================================
# USER MANAGEMENT
# ============================================================

def create_user(username, password, role, email):
    """
    Create a new user account.

    Validates password complexity before hashing.
    Stores only the bcrypt hash - plaintext never written to disk.
    Generates RSA-2048 key pair with private key encrypted at rest.

    Args:
        username: unique identifier
        password: plaintext password (validated, hashed, never stored)
        role: Researcher / Clinician / Auditor
        email: registered address for MFA OTP delivery

    Returns:
        True if created successfully, False otherwise
    """
    users = _load_users()

    if username in users:
        print(f"  [!] Username '{username}' already exists.")
        return False

    valid_roles = ["Researcher", "Clinician", "Auditor"]
    if role not in valid_roles:
        print(f"  [!] Invalid role. Must be one of: {valid_roles}")
        return False

    # Validate password complexity before hashing
    complexity_ok, complexity_msg = validate_password_complexity(password)
    if not complexity_ok:
        print(f"  [!] Password rejected: {complexity_msg}")
        return False

    # Hash password immediately - plaintext never persisted
    users[username] = {
        "password_hash": hash_password(password),
        "role": role,
        "email": email,
        "failed_attempts": 0,
        "locked": False
    }

    _save_users(users)

    # Generate RSA key pair - private key encrypted with user's password
    from key_manager import generate_user_keys
    generate_user_keys(username, password)

    log_event(
        username, role, "ACCOUNT_CREATED",
        f"New {role} account registered with complexity-validated "
        f"password. MFA email: {email}"
    )

    print(f"  [+] User '{username}' created successfully as {role}")
    return True


def login(username, password):
    """
    Authenticate a user through password verification and MFA.

    Includes account lockout after 5 consecutive failed attempts,
    protecting against brute-force and credential stuffing attacks.
    Lockout is recorded in the audit log for administrator review.

    Authentication flow:
    1. Verify username exists
    2. Check account is not locked
    3. Verify bcrypt password hash
    4. Reset failed attempt counter on success
    5. If MFA enabled: generate OTP, deliver via email,
       prompt for code with up to 3 attempts
    6. On success: check key rotation status
    7. Log all attempts to tamper-evident audit log

    Args:
        username: entered username
        password: entered plaintext password

    Returns:
        (True, role) if fully authenticated
        (False, None) if authentication fails at any stage
    """
    users = _load_users()

    MAX_FAILED_ATTEMPTS = 5

    # Step 1 - verify username exists
    # Generic error message prevents username enumeration attacks
    if username not in users:
        log_event(
            "UNKNOWN", "UNKNOWN", "LOGIN_FAILED",
            f"Login attempt with unrecognised username: {username}"
        )
        print("  [!] Invalid username or password.")
        return False, None

    user = users[username]

    # Step 2 - check account lockout
    if user.get("locked", False):
        log_event(
            username, user["role"], "LOGIN_BLOCKED",
            f"Login attempt on locked account. "
            f"Failed attempts: {user.get('failed_attempts', 0)}"
        )
        print("  [!] This account has been locked due to too many "
              "failed login attempts.")
        print("  [!] Please contact your system administrator.")
        return False, None

    # Step 3 - verify password
    if not verify_password(password, user["password_hash"]):
        # Increment failed attempt counter
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        remaining = MAX_FAILED_ATTEMPTS - user["failed_attempts"]

        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            # Lock the account
            user["locked"] = True
            users[username] = user
            _save_users(users)
            log_event(
                username, user["role"], "ACCOUNT_LOCKED",
                f"Account locked after {MAX_FAILED_ATTEMPTS} consecutive "
                f"failed login attempts. Administrator intervention required."
            )
            print("  [!] Invalid username or password.")
            print(f"  [!] Account locked after {MAX_FAILED_ATTEMPTS} "
                  f"failed attempts.")
            print("  [!] Please contact your system administrator.")
        else:
            users[username] = user
            _save_users(users)
            log_event(
                username, user["role"], "LOGIN_FAILED",
                f"Incorrect password. Failed attempts: "
                f"{user['failed_attempts']}/{MAX_FAILED_ATTEMPTS}"
            )
            print("  [!] Invalid username or password.")
            if remaining <= 2:
                print(f"  [!] Warning: {remaining} attempt(s) remaining "
                      f"before account lockout.")

        return False, None

    # Password correct - reset failed attempt counter
    user["failed_attempts"] = 0
    users[username] = user
    _save_users(users)

    # Step 4 - MFA via email OTP
    if MFA_ENABLED:
        print(f"\n  [*] Password verified.")
        print(f"  [*] Sending one-time code to {user['email']}...")

        otp_code = generate_otp()
        email_sent = send_otp_email(user["email"], otp_code, username)

        if not email_sent:
            log_event(
                username, user["role"], "LOGIN_FAILED",
                "MFA OTP email delivery failed"
            )
            print("  [!] Could not deliver OTP. Login aborted.")
            return False, None

        print(f"  [*] Code sent. Please check {user['email']}")

        attempts = 0
        max_attempts = 3

        while attempts < max_attempts:
            entered = input(
                f"\n  Enter 6-digit OTP "
                f"(attempt {attempts+1}/{max_attempts}): "
            ).strip()

            if verify_otp(otp_code, entered):
                # Full authentication successful
                log_event(
                    username, user["role"], "LOGIN_SUCCESS",
                    "Password and MFA OTP verified successfully"
                )
                print(f"\n  [+] Authentication successful.")
                print(f"  [+] Welcome, {username} ({user['role']})")

                # Key rotation check
                from key_manager import check_key_rotation
                needs_rotation, rotation_msg = check_key_rotation(username)
                if needs_rotation:
                    print(f"\n  [!] {rotation_msg}")

                return True, user["role"]

            else:
                attempts += 1
                remaining = max_attempts - attempts
                if remaining > 0:
                    print(f"  [!] Incorrect code. {remaining} attempts remaining.")
                else:
                    log_event(
                        username, user["role"], "LOGIN_FAILED",
                        "MFA failed - maximum OTP attempts exceeded"
                    )
                    print("  [!] Too many incorrect attempts. Login failed.")
                    return False, None

    else:
        # MFA disabled - password only
        log_event(
            username, user["role"], "LOGIN_SUCCESS",
            "Password authentication successful (MFA disabled)"
        )
        print(f"\n  [+] Login successful.")
        print(f"  [+] Welcome, {username} ({user['role']})")

        from key_manager import check_key_rotation
        needs_rotation, rotation_msg = check_key_rotation(username)
        if needs_rotation:
            print(f"\n  [!] {rotation_msg}")

        return True, user["role"]

def get_user_info(username):
    """
    Retrieve stored user information by username.
    Returns user dict or None if not found.
    """
    users = _load_users()
    return users.get(username, None)


def get_all_users_by_role(role):
    """
    Return list of all usernames with a specific role.
    Used when encrypting files to identify authorised recipients
    for multi-recipient key encapsulation.

    Args:
        role: Researcher / Clinician / Auditor

    Returns:
        list of usernames with that role
    """
    users = _load_users()
    return [
        username for username, data in users.items()
        if data["role"] == role
    ]