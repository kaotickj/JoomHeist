# Joomla Content History SQL Injection: Session Hijacking PoC Writeup

## Overview

This proof-of-concept (PoC) demonstrates a critical **SQL Injection vulnerability** in the **Content History component** of Joomla CMS versions **3.2 through 3.4.4**, previously assigned CVEs including [CVE-2015-7297](https://nvd.nist.gov/vuln/detail/CVE-2015-7297) and related identifiers. While the vulnerability has been publicly documented, this PoC provides a novel, fully automated Python script for exploiting the flaw to:

* Detect Joomla database table prefixes automatically.
* Enumerate Joomla Super User accounts.
* Extract active administrator session IDs directly from the database.
* Detect the Joomla session cookie name dynamically.
* Provide a ready-to-use session cookie string for administrative backend hijacking.

---

## Vulnerability Details

* **Component affected:** `com_contenthistory` (Content History administrator component)
* **Versions affected:** Joomla 3.2 up to 3.4.4 inclusive
* **Vulnerability type:** Blind/Error-based SQL Injection via unsanitized `list[select]` parameter in the history view.
* **Impact:** Unauthorized retrieval of privileged data, including active Super User session IDs, enabling full administrative access to Joomla backend without credentials.

The vulnerability arises due to the lack of input sanitization on the `list[select]` GET parameter, allowing attackers to inject crafted SQL queries that leverage MySQL error conditions to extract data via error messages.

---

## How the PoC Script Works

This Python 3 script uses the following techniques:

### 1. Table Prefix Detection

* Joomla databases use a configurable table prefix, typically 3-6 characters plus underscore, e.g. `jym13`.
* The script injects a crafted SQL payload designed to trigger a MySQL duplicate entry error referencing the `*_ucm_history` table.
* Parsing the error message reveals the actual database table prefix.

### 2. Super User Enumeration

* Once the prefix is known, the script iterates through the users linked to the `Super Users` group (`group_id=8`).
* Using error-based injection, it enumerates usernames of Super Users one-by-one from the `*_users` table.

### 3. Session ID Extraction

* The script then targets the `*_session` table to extract active session IDs of logged-in Super Users.
* The SQL payload searches for sessions where `data` contains `Super User`.
* Since the injection concatenates the session ID with a random digit (0 or 1) to trigger a MySQL error, the script removes this trailing digit to retrieve the clean session ID.

### 4. Cookie Name Detection

* The script performs an HTTP GET request to the Joomla administrator endpoint (`/administrator/`).
* It inspects cookies sent by the server to detect the actual Joomla session cookie name (which may vary by installation/config).
* If detection fails, it defaults to the standard cookie name `joomla_session`.

---

## Usage Instructions

1. **Update the target URL**

   Change the `TARGET` variable in the script to point to the vulnerable Joomla instance’s front-end index page (ending with `index.php`), e.g.:

   ```python
   TARGET = "http://10.0.2.13/joom330/index.php"
   ```

2. **Run the script**

   Execute with Python 3:

   ```bash
   python3 joomla_sqli_poc.py
   ```

3. **Interpret output**

   The script will:

   * Print the detected Joomla database prefix.
   * Enumerate and display Super User accounts.
   * Extract and display the active session ID of a logged-in Super User.
   * Detect and display the Joomla session cookie name.
   * Provide a complete cookie string for hijacking the admin session.

4. **Hijack admin session**

   Use the output cookie string in your browser's devtools under Storage > Cookies, or with curl:

   ```bash
   curl -b 'joomla_session=cl16d18nr00pqm077ohurhqtk3' http://10.0.2.13/joom330/administrator/
   ```

   This grants direct authenticated access to the Joomla administrator backend without credentials.

---

# DISCLAIMER:
> This script is intended for authorized security testing and educational purposes only.
> Unauthorized access or exploitation of systems without explicit written permission is illegal
> and unethical. Use responsibly and within the boundaries of applicable laws and policies.
