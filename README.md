# WinEventLog Incident Investigation Starter (Beginner Friendly)

This project is a **hands-on beginner cybersecurity lab** that teaches how to investigate **Windows Security Event Logs** for possible security incidents using **PowerShell**.

It focuses on **defensive security** and **log analysis**, the same foundation used by SOC analysts, incident responders, and blue team professionals.

This project does **not** hack systems, exploit vulnerabilities, or modify Windows settings.  
It only **reads existing logs** and summarizes them.

---

## What you will learn

By completing this project, you will learn how to:

- Understand what Windows Event Logs are and why they matter
- Identify important security-related Event IDs
- Safely read Security logs using PowerShell
- Export logs into a CSV file for investigation
- Detect suspicious patterns such as repeated failed logons
- Interpret investigation results like a security analyst
- Document findings in a clear, professional way for GitHub or a resume

---

## Project structure

WinEventLog-Incident-Starter/
├─ README.md
├─ scripts/
│ ├─ export-security-events.ps1
│ └─ hunt-suspicious-events.ps1
└─ sample-data/
└─ exported-security-events.csv (created after running export script)

yaml
Copy code

---

## Safety and trust statement (important)

This project is **safe to run on your own PC**.

The scripts:
- Only **read** Windows logs
- Do **not** create users
- Do **not** delete files
- Do **not** change registry settings
- Do **not** disable antivirus or security features

The PowerShell commands used are read-only analysis commands such as:
- `Get-WinEvent`
- `Select-Object`
- `Group-Object`
- `Export-Csv`

No permanent system changes are made.

---

## Requirements

- Windows 10 or Windows 11
- PowerShell
- Administrator access (required to read the Security log)

---

## Important Windows Event IDs used

These Event IDs are commonly used in real-world investigations:

| Event ID | Description |
|--------:|------------|
| 4625 | Failed logon attempt |
| 4624 | Successful logon |
| 4634 | User logoff |
| 4672 | Special privileges assigned (often admin logon) |
| 5379 | Credential Manager credentials were read |

Note: Event ID **5379 is not a logon attempt**. It only means stored credentials were accessed.

---

## How this project works (concept overview)

### Script 1: `export-security-events.ps1`

This script:
1. Reads selected Event IDs from the Windows **Security** log
2. Collects useful information such as:
   - Time of event
   - Event ID
   - Message details
3. Exports the data into a CSV file for review

Why this matters:
- Security analysts often export logs as evidence
- CSV files allow filtering, searching, and reporting

Output:
- `sample-data/exported-security-events.csv`

---

### Script 2: `hunt-suspicious-events.ps1`

This script performs a basic investigation:

1. Reads failed (4625) and successful (4624) logons
2. Extracts key fields:
   - Account name
   - Logon type
   - Source IP address
3. Counts how many failures each account has
4. Flags accounts with:
   - Many failed logons
   - At least one successful logon
5. Displays the most recent failed logon events for manual review

This simulates how analysts look for **password guessing or brute-force behavior**.

---

## Step-by-step: How to run this project

### Step 1: Open PowerShell as Administrator

1. Click **Start**
2. Type **PowerShell**
3. Right-click **Windows PowerShell**
4. Select **Run as administrator**
5. Click **Yes**

This is required to read the Security log.

---

### Step 2: Navigate to the project folder

Example:
```powershell
cd D:\Desktop\WinEventLog-Incident-Starter
Verify:

powershell
Copy code
pwd
Step 3: Allow scripts for this session only
Run:

powershell
Copy code
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
When prompted, type:

css
Copy code
Y
This change:

Applies only to the current PowerShell window

Automatically resets when the window is closed

Does not affect future sessions

Step 4: Verify scripts exist
powershell
Copy code
dir scripts
Expected files:

export-security-events.ps1

hunt-suspicious-events.ps1

Step 5: Run the export script
powershell
Copy code
.\scripts\export-security-events.ps1
Result:

A CSV file is created in sample-data

You can open it in Excel and inspect events manually

What to search in Excel:

4625 for failed logons

4624 for successful logons

Step 6: Run the investigation script
powershell
Copy code
.\scripts\hunt-suspicious-events.ps1
This prints the investigation results directly in PowerShell.

If you see no failed logons (common issue)
Modern Windows authentication methods (Windows Hello, cached credentials) do not always generate 4625 events.

To reliably generate test data:

Safe test method using runas
Open Command Prompt (normal user, not admin)

Run:

cmd
Copy code
runas /user:student01 cmd
Enter a wrong password multiple times until it fails

This guarantees Event ID 4625 is created.

Then rerun:

powershell
Copy code
.\scripts\hunt-suspicious-events.ps1
How to read and understand the results
Example output: Failed logon summary
pgsql
Copy code
Top accounts with FAILED logons (4625)

Name        Count
----        -----
LAB-PC$        8
student01     3
Interpretation:

LAB-PC$ is a computer account (machine accounts end with $)

student01 is a user account

Machine accounts commonly generate background failures and are not automatically malicious

Example output: Potential incident section
yaml
Copy code
POTENTIAL INCIDENT:
Account: student01
Failed logons: 6
First fail time: 01/10/2026 14:22:11
Success time: 01/10/2026 14:30:55
Success logon type: 10
Success source IP: 192.168.1.25
Interpretation:

Multiple failed attempts occurred

A successful logon followed shortly after

Logon Type 10 means Remote Desktop

This pattern can suggest password guessing or misuse

This is a learning detector, so analysts must still verify timelines and context.

Example output: Last failed logons
swift
Copy code
TimeCreated            AccountName  LogonType  IpAddress
-----------            -----------  ---------  ---------
1/10/2026 14:29:01 PM  student01    2          ::1
1/10/2026 14:28:22 PM  student01    2          127.0.0.1
Interpretation:

Logon Type 2 = local interactive login

127.0.0.1 and ::1 mean localhost

These failures came from the same machine, not an external attacker

Logon type reference (important)
Logon Type	Meaning
2	Interactive (keyboard login)
3	Network (file share, service access)
5	Service logon
10	Remote Desktop (RDP)

Example investigation conclusion
Finding:
Multiple failed logons were detected for user student01, followed by a successful logon.

Assessment:
Based on local IP addresses and logon type, activity appears consistent with user testing or mis-typed credentials.

Recommendation:

Continue monitoring failed logons

Enforce strong passwords

Review RDP exposure if applicable

Troubleshooting
Error: Unauthorized operation
Cause:

PowerShell not run as Administrator

Fix:

Reopen PowerShell using “Run as administrator”

Script runs but shows no failures
Cause:

No 4625 events in the time window

Fix:

Generate test failures using runas

Increase time range from 7 days to 30 days in the script

Next improvements (optional)
To expand this project:

Detect success events only after failures (reduce false positives)

Add RDP-focused detection (Logon Type 10)

Export a timeline report CSV

Investigate admin activity using Event ID 4672

Add user creation and group changes (4720, 4728, 4732)