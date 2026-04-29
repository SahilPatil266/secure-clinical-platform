# main.py
# Entry point for the SecureClinical platform.
#
# On first run, creates one test account per role as required by the brief.
# Subsequent runs go straight to the login screen.
#
# Test accounts created:
#   Researcher : alice_researcher / Research@123
#   Clinician  : bob_clinician    / Clinician@123
#   Auditor    : carol_auditor    / Auditor@123

import os
from getpass import getpass
from auth import create_user, login
from roles import researcher_menu, clinician_menu, auditor_menu
from audit import log_event

USERS_FILE = "users.json"

BANNER = """
╔══════════════════════════════════════════════════════════╗
║         SecureClinical Collaboration Platform            ║
║         Cryptographic Security System v1.0               ║
║                                                          ║
║  Securing cross-border clinical research data            ║
║  AES-256-GCM · RSA-2048 · bcrypt · MFA · Audit Chain    ║
╚══════════════════════════════════════════════════════════╝
"""


def create_test_accounts():
    """
    Create one test account per role on first run.
    Called only if users.json does not yet exist.

    Test accounts use strong passwords meeting complexity requirements:
    uppercase, lowercase, digit, special character, minimum 8 characters.

    In a production deployment, accounts would be provisioned by a
    system administrator through a secure onboarding process.
    These test accounts exist solely to demonstrate system functionality
    across all three roles as required by the assessment brief.
    """
    print("\n  [*] First run detected - creating test accounts...")
    print("  [*] Please enter email addresses for MFA OTP delivery.\n")

    # Researcher account
    print("  --- Researcher Account ---")
    researcher_email = input(
        "  Email for Bob_Researcher (receives OTP): "
    ).strip()
    create_user(
        username="Bob_Researcher",
        password="Research@123",
        role="Researcher",
        email=researcher_email
    )

    # Clinician account
    print("\n  --- Clinician Account ---")
    clinician_email = input(
        "  Email for Tanya_Clinician (receives OTP): "
    ).strip()
    create_user(
        username="Tanya_Clinician",
        password="Clinician@123",
        role="Clinician",
        email=clinician_email
    )

    # Auditor account
    print("\n  --- Auditor Account ---")
    auditor_email = input(
        "  Email for MrRobot_Auditor (receives OTP): "
    ).strip()
    create_user(
        username="MrRobot_Auditor",
        password="Auditor@123",
        role="Auditor",
        email=auditor_email
    )

    print("\n  [+] All test accounts created successfully.")
    print("\n  Test credentials:")
    print("  ┌─────────────────────┬─────────────────┬────────────┐")
    print("  │ Username            │ Password        │ Role       │")
    print("  ├─────────────────────┼─────────────────┼────────────┤")
    print("  │ Bob_Researcher      │ Research@123    │ Researcher │")
    print("  │ Tanya_Clinician     │ Clinician@123   │ Clinician  │")
    print("  │ MrRobot_Auditor     │ Auditor@123     │ Auditor    │")
    print("  └─────────────────────┴─────────────────┴────────────┘")

def login_screen():
    """
    Display login prompt and authenticate user.

    Returns:
        (username, role) if authentication successful
        (None, None) if user chooses to exit
    """
    print("\n  Please log in to continue.")
    print("  (Type 'exit' to quit)\n")

    username = input("  Username: ").strip()

    if username.lower() == "exit":
        return None, None

    password = getpass("  Password: ")

    success, role = login(username, password)

    if success:
        return username, role
    else:
        return None, None


def route_to_menu(username, role):
    """
    Route authenticated user to their role-specific menu.

    Args:
        username: authenticated username
        role: verified role from users.json
    """
    if role == "Researcher":
        researcher_menu(username)
    elif role == "Clinician":
        clinician_menu(username)
    elif role == "Auditor":
        auditor_menu(username)
    else:
        print(f"  [!] Unknown role: {role}. Access denied.")
        log_event(username, role, "ACCESS_DENIED",
                 f"Unknown role '{role}' attempted system access")


def main():
    """
    Main application loop with graceful error handling.

    Flow:
    1. Display banner
    2. Create test accounts if first run
    3. Login loop - authenticate and route to role menu
    4. After logout, return to login screen
    """
    print(BANNER)

    try:
        # First run setup
        if not os.path.exists(USERS_FILE):
            create_test_accounts()

        # Main login loop
        while True:
            print("\n" + "="*60)
            print("  LOGIN")
            print("="*60)

            username, role = login_screen()

            if username is None:
                print("\n" + "="*60)
                another = input(
                    "  Another user login? (y/n): "
                ).strip().lower()
                if another != "y":
                    print("\n  Exiting SecureClinical Platform. Goodbye.")
                    break
                continue

            try:
                route_to_menu(username, role)
            except KeyboardInterrupt:
                print(f"\n\n  Session interrupted.")
                log_event(username, role, "SESSION_INTERRUPTED",
                        "User session ended via keyboard interrupt")

            print("\n" + "="*60)
            another = input(
                "  Another user login? (y/n): "
            ).strip().lower()

            if another != "y":
                print("\n  Exiting SecureClinical Platform. Goodbye.")
                break

    except KeyboardInterrupt:
        print("\n\n  Platform shutdown. Goodbye.")
    except Exception as e:
        print(f"\n  [!] Unexpected system error: {e}")
        print(f"  [!] Please contact your system administrator.")

if __name__ == "__main__":
    main()