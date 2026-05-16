<#
===============================
EXPORT SECURITY EVENTS (BEGINNER)
===============================

What this script is for:
- Windows stores important “who logged in, who failed to log in, who got admin rights” records
  inside a place called the Security Event Log.
- When you investigate a security incident, you usually need to collect those events first.
- This script exports a small set of important Security events into a CSV file
  so you can read it easily or attach it to a report.

Important notes:
- The Security log often requires Admin permission to read.
- If you get “Access is denied”, run PowerShell as Administrator.

Output:
- sample-data\exported-security-events.csv
#>

# -----------------------------
# 1) Choose which Event IDs to export
# -----------------------------
# Event IDs are like “labels” that tell you what type of event happened.
# We are selecting a small set that helps in many beginner investigations:
# 4624 = Successful logon (someone logged in successfully)
# 4625 = Failed logon (someone tried to log in but failed)
# 4634 = Logoff (a user logged out)
# 4672 = Special privileges assigned (often means admin-level logon)
$eventIds = 4624, 4625, 4634, 4672

# -----------------------------
# 2) Choose how far back we want to look
# -----------------------------
# Logs can be huge. Looking back “forever” is slow.
# For learning, last 7 days is a good default.
$startTime = (Get-Date).AddDays(-7)

# -----------------------------
# 3) Pull the events from the Windows Security log
# -----------------------------
# Get-WinEvent reads Windows logs.
# -FilterHashtable is the recommended way because it is faster and more efficient
# than pulling everything and filtering later.
#
# LogName = 'Security' means we are reading the Security event log.
# Id      = $eventIds means only those event types.
# StartTime means only events after that date/time.
#
# -ErrorAction SilentlyContinue:
# Sometimes Windows might block a few events or you might not have permission.
# This avoids the script stopping and keeps it beginner-friendly.
$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = $eventIds
    StartTime = $startTime
} -ErrorAction SilentlyContinue

# -----------------------------
# 4) Select the most useful fields for investigation
# -----------------------------
# TimeCreated = when it happened (critical for timelines)
# Id = event ID (4624, 4625, etc.)
# ProviderName = which system generated it (usually “Microsoft-Windows-Security-Auditing”)
# LevelDisplayName = severity label (Informational, Warning, Error)
# Message = the full human-readable details (THIS is where you find username, IP, logon type)
#
# For serious investigations you might parse Message into separate fields,
# but for beginners, exporting Message is a good starting point.
$results = $events | Select-Object `
    TimeCreated,
    Id,
    ProviderName,
    LevelDisplayName,
    Message

# -----------------------------
# 5) Create an output folder if it doesn't exist
# -----------------------------
# $PSScriptRoot is the folder where THIS script is located.
# We go one folder up ".." then into "sample-data".
$outDir = Join-Path $PSScriptRoot "..\sample-data"

# New-Item -Force:
# - Creates the folder if missing
# - Does nothing if it already exists
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# -----------------------------
# 6) Export to CSV
# -----------------------------
# CSV is easy to open in Excel or Google Sheets.
# UTF8 ensures characters display correctly.
$outFile = Join-Path $outDir "exported-security-events.csv"
$results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outFile

# -----------------------------
# 7) Print a friendly success message
# -----------------------------
Write-Host "Export complete!"
Write-Host "File created: $outFile"
Write-Host "Tip: Open it in Excel, then search for 4625 (failed logons) and 4624 (success logons)."
