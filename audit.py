# audit.py
# Implements a tamper-evident chained audit log for the SecureClinical platform.
#
# Each log entry contains a SHA-256 hash of the previous entry, creating a
# chain where any modification to a historical entry invalidates all subsequent
# hashes. This approach mirrors the integrity guarantees of blockchain structures
# and directly satisfies GDPR Article 5(2) accountability requirements and
# Article 30 records of processing obligations.

import json
import os
import hashlib
from datetime import datetime

AUDIT_LOG_FILE = "audit_log.json"


def _hash_entry(content):
    """
    Compute SHA-256 hash of an entry's content string.
    Kept internal to audit.py to avoid circular imports.
    """
    return hashlib.sha256(content.encode()).hexdigest()


def _load_log():
    """Load existing audit log from file, or return empty list if none exists."""
    if os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, "r") as f:
            return json.load(f)
    return []


def _save_log(log):
    """Save audit log to file."""
    with open(AUDIT_LOG_FILE, "w") as f:
        json.dump(log, f, indent=4)


def log_event(username, role, action, details=""):
    """
    Record a new event in the chained audit log.

    Each entry is hashed and linked to the previous entry's hash.
    This means:
    - If entry 3 is modified, entry 4's previous_hash no longer matches
    - The chain break is detectable by verify_log_integrity()
    - This provides cryptographic evidence of tampering

    Args:
        username: the user performing the action
        role: their role (Researcher, Clinician, Auditor)
        action: what they did (e.g. ENCRYPT_FILE, LOGIN)
        details: optional additional context
    """
    log = _load_log()

    # Get the hash of the last entry to chain to
    # If this is the first entry, use a known genesis value
    if len(log) == 0:
        previous_hash = "GENESIS"
    else:
        previous_hash = log[-1]["entry_hash"]

    # Build the log entry
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": username,
        "role": role,
        "action": action,
        "details": details,
        "previous_hash": previous_hash
    }

    # Hash the entire entry content to create this entry's hash
    # This hash will be referenced by the next entry
    entry_content = (f"{entry['timestamp']}{entry['username']}"
                    f"{entry['role']}{entry['action']}"
                    f"{entry['details']}{entry['previous_hash']}")
    entry["entry_hash"] = _hash_entry(entry_content)

    log.append(entry)
    _save_log(log)


def verify_log_integrity():
    """
    Verify the integrity of the entire audit log chain.

    Recomputes every entry's hash and checks that each entry's
    previous_hash matches the actual hash of the preceding entry.
    Any break in the chain indicates tampering.

    Returns:
        (True, message) if chain is unbroken
        (False, details) if tampering detected, with location
    """
    log = _load_log()

    if len(log) == 0:
        return True, "Log is empty - no entries to verify."

    for i, entry in enumerate(log):
        # Recompute what this entry's hash should be
        entry_content = (f"{entry['timestamp']}{entry['username']}"
                        f"{entry['role']}{entry['action']}"
                        f"{entry['details']}{entry['previous_hash']}")
        expected_hash = _hash_entry(entry_content)

        # Check this entry's stored hash matches recomputed hash
        if entry["entry_hash"] != expected_hash:
            return False, (f"Tampering detected at entry {i+1} "
                          f"(timestamp: {entry['timestamp']})")

        # Check this entry's previous_hash matches the actual previous entry
        if i > 0:
            actual_previous_hash = log[i-1]["entry_hash"]
            if entry["previous_hash"] != actual_previous_hash:
                return False, (f"Chain break detected at entry {i+1} "
                              f"- previous hash mismatch")

    return True, (f"Log integrity verified. "
                 f"{len(log)} entries checked, chain intact.")


def view_log():
    """
    Return all audit log entries for display.
    Used by Auditors to review system activity.
    """
    log = _load_log()
    if len(log) == 0:
        return "No audit log entries found."

    output = []
    output.append(f"{'='*60}")
    output.append(f"AUDIT LOG - {len(log)} entries")
    output.append(f"{'='*60}")

    for i, entry in enumerate(log):
        output.append(f"\nEntry {i+1}:")
        output.append(f"  Timestamp : {entry['timestamp']}")
        output.append(f"  User      : {entry['username']} ({entry['role']})")
        output.append(f"  Action    : {entry['action']}")
        if entry['details']:
            output.append(f"  Details   : {entry['details']}")
        output.append(f"  Hash      : {entry['entry_hash'][:20]}...")

    return "\n".join(output)