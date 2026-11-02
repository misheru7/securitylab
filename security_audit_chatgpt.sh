#!/usr/bin/env bash

# Security Audit - Rocky Linux 10 / Ubuntu 26.04
# Run as root. Read-only checks except report creation.
# Exit: 0 = no findings, 1 = findings, 2 = audit error.

set -uo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

AUDIT_DIR="/var/log/security-audit2"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
REPORT="$AUDIT_DIR/audit-${TIMESTAMP}-$$.log"

FINDINGS=0
ERRORS=0

# Require root for shadow and journal access.
if (( EUID != 0 )); then
    echo "ERROR: Run this script as root." >&2
    exit 2
fi

# Verify required commands are available.
for cmd in date awk getent journalctl ss \
           mkdir mktemp mv cat grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Missing command: $cmd" >&2
        exit 2
    fi
done

# Create a private report directory if necessary.
if ! mkdir -p -m 0700 -- "$AUDIT_DIR"; then
    echo "ERROR: Cannot create audit directory." >&2
    exit 2
fi

# Avoid following a pre-existing directory symlink.
if [[ -L "$AUDIT_DIR" || ! -d "$AUDIT_DIR" ]]; then
    echo "ERROR: Unsafe audit directory." >&2
    exit 2
fi

TMP_REPORT=$(mktemp "$AUDIT_DIR/.audit.XXXXXXXX") || exit 2
trap 'rm -f -- "$TMP_REPORT"' EXIT

# Write all output into the private report.
exec 3>&1
exec >"$TMP_REPORT" 2>&1

echo "========================================"
echo "SECURITY AUDIT REPORT"
echo "Host: $(hostname)"
echo "Timestamp (UTC): $(date -u)"
echo "========================================"

# ----------------------------------------
# 1. Failed SSH authentication (24 hours)
# ----------------------------------------
echo
echo "=== FAILED SSH LOGINS - LAST 24 HOURS ==="

# Read journal records from both common SSH units.
# Journal timestamps provide the 24-hour boundary.
SSH_LOG=$(mktemp "$AUDIT_DIR/.ssh.XXXXXXXX") || exit 2

if journalctl --since "24 hours ago" \
    -u ssh.service -u sshd.service \
    --no-pager -o short-iso --quiet \
    >"$SSH_LOG"; then

    SSH_FAILURES=$(grep -Eic \
        'Failed (password|publickey|keyboard-interactive)|authentication failure|Invalid user|maximum authentication attempts' \
        "$SSH_LOG" || true)

    echo "Matching SSH failure events: $SSH_FAILURES"

    if (( SSH_FAILURES > 0 )); then
        grep -Ei \
            'Failed (password|publickey|keyboard-interactive)|authentication failure|Invalid user|maximum authentication attempts' \
            "$SSH_LOG" || true
        ((FINDINGS++))
    else
        echo "No matching failed SSH events."
    fi
else
    echo "ERROR: Unable to read SSH journal."
    ((ERRORS++))
fi

rm -f -- "$SSH_LOG"

# ----------------------------------------
# 2. Accounts with UID 0
# ----------------------------------------
echo
echo "=== ACCOUNTS WITH UID 0 ==="

if PASSWD_DATA=$(getent passwd); then
    UID_ZERO=$(printf '%s\n' "$PASSWD_DATA" |
        awk -F: '$3 == 0 {print $1 " (UID 0)"}')

    if [[ -n "$UID_ZERO" ]]; then
        printf '%s\n' "$UID_ZERO"

        # Root is expected; additional UID 0 accounts
        # are treated as security findings.
        if printf '%s\n' "$PASSWD_DATA" |
            awk -F: '$3 == 0 && $1 != "root" {found=1}
                      END {exit !found}'; then
            echo "WARNING: Additional UID 0 account detected."
            ((FINDINGS++))
        fi
    else
        echo "ERROR: No UID 0 account found."
        ((ERRORS++))
    fi
else
    echo "ERROR: Unable to enumerate user accounts."
    ((ERRORS++))
fi

# ----------------------------------------
# 3. Accounts with empty passwords
# ----------------------------------------
echo
echo "=== ACCOUNTS WITH EMPTY PASSWORD FIELDS ==="

# getent shadow includes supported NSS sources.
if SHADOW_DATA=$(getent shadow); then
    EMPTY_ACCOUNTS=$(printf '%s\n' "$SHADOW_DATA" |
        awk -F: '$2 == "" {print $1}')

    if [[ -n "$EMPTY_ACCOUNTS" ]]; then
        printf '%s\n' "$EMPTY_ACCOUNTS"
        echo "WARNING: Empty password field detected."
        ((FINDINGS++))
    else
        echo "No empty password fields detected."
    fi
else
    echo "ERROR: Unable to read shadow database."
    ((ERRORS++))
fi

# ----------------------------------------
# 4. Listening TCP and UDP ports
# ----------------------------------------
echo
echo "=== LISTENING TCP/UDP PORTS ==="

if ss -H -tulnp; then
    echo "Listening socket enumeration completed."
else
    echo "ERROR: Unable to enumerate listening ports."
    ((ERRORS++))
fi

# ----------------------------------------
# 5. Final audit status
# ----------------------------------------
echo
echo "========================================"
echo "AUDIT SUMMARY"
echo "Security finding categories: $FINDINGS"
echo "Audit errors: $ERRORS"

if (( ERRORS > 0 )); then
    STATUS=2
    echo "RESULT: INCOMPLETE - AUDIT ERROR"
elif (( FINDINGS > 0 )); then
    STATUS=1
    echo "RESULT: SECURITY FINDINGS DETECTED"
else
    STATUS=0
    echo "RESULT: NO FINDINGS DETECTED"
fi

echo "========================================"

# Publish report atomically.
if ! mv -n -- "$TMP_REPORT" "$REPORT"; then
    echo "ERROR: Cannot save report." >&3
    exit 2
fi

trap - EXIT
echo "Audit report: $REPORT" >&3
exit "$STATUS"
