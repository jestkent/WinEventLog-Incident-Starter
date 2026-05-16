<#
=========================================
HUNT SUSPICIOUS LOGON PATTERNS (BEGINNER)
=========================================

What this script is for:
- A common incident pattern is:
  1) Many failed login attempts (Event ID 4625)
  2) Then a successful login (Event ID 4624)
- That can suggest password guessing / brute force, or someone trying many passwords.

What this script does:
- Collects 4624 and 4625 events from the last 7 days
- Extracts beginner-friendly fields (AccountName, LogonType, IP Address)
- Shows which accounts have the most failed attempts
- Checks if any “failed then success” sequence exists for top accounts

Important note:
- Windows event messages are long text. In professional tools, we parse XML fields.
- For beginners, we do a simple text-based extraction.
  It's not perfect, but it works well enough to learn investigation logic.
#>

# -----------------------------
# 1) Time window (last 7 days)
# -----------------------------
$startTime = (Get-Date).AddDays(-7)

# -----------------------------
# 2) Pull only logon events we care about
# -----------------------------
# 4625 = failed logon
# 4624 = successful logon
$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624, 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue

# -----------------------------
# 3) Helper function: extract a field value from the text Message
# -----------------------------
# Event Viewer shows fields like:
# "Account Name: John"
# "Logon Type: 10"
# "Source Network Address: 192.168.1.20"
#
# This function:
# - Splits the message into lines
# - Finds the first line that starts with "FieldName:"
# - Returns the text after the colon
function Get-FieldValueFromMessage {
    param(
        [string]$Message,
        [string]$FieldName
    )

    # Split message into lines. `n = newline.
    $lines = $Message -split "`n"

    # Find the line that begins with "FieldName:"
    # Trim() removes spaces at the start so matching is easier.
    # $line = $lines | Where-Object { $_.Trim().StartsWith("$FieldName:") } | Select-Object -First 1
    $line = $lines | Where-Object { $_.Trim().StartsWith("${FieldName}:") } | Select-Object -First 1


    # If the field doesn't exist in the message, return an empty string
    if (-not $line) { return "" }

    # Split only into 2 pieces at the first colon
    # Example: "Account Name: John" -> ["Account Name", " John"]
    return ($line -split ":", 2)[1].Trim()
}

# -----------------------------
# 4) Convert each raw event into a simple object (structured data)
# -----------------------------
# Raw Windows events are complex.
# We convert them into a consistent table with only the fields we want.
$parsed = foreach ($e in $events) {
    $msg = $e.Message

    [PSCustomObject]@{
        # When it happened
        TimeCreated = $e.TimeCreated

        # Which event type (4624 or 4625)
        EventId     = $e.Id

        # Who the event is about (username)
        AccountName = (Get-FieldValueFromMessage -Message $msg -FieldName "Account Name")

        # How the login happened:
        # 2  = local interactive (keyboard login)
        # 3  = network (file share, etc.)
        # 10 = Remote Desktop (RDP)
        LogonType   = (Get-FieldValueFromMessage -Message $msg -FieldName "Logon Type")

        # Where it came from (often blank for local logons)
        IpAddress   = (Get-FieldValueFromMessage -Message $msg -FieldName "Source Network Address")
    }
}

# -----------------------------
# 5) Count failed logons per account
# -----------------------------
# Filter only 4625 events (failures), then group by AccountName.
# Sort so the accounts with the most failures appear at the top.
$failedCounts = $parsed |
    Where-Object { $_.EventId -eq 4625 -and $_.AccountName } |
    Group-Object AccountName |
    Sort-Object Count -Descending

Write-Host "========================================"
Write-Host "Top accounts with FAILED logons (4625)"
Write-Host "Time window: last 7 days"
Write-Host "========================================"
$failedCounts | Select-Object Name, Count | Format-Table -AutoSize

# -----------------------------
# 6) Check for the pattern: many fails then a success
# -----------------------------
# Why this matters:
# - Many failures might be a user forgetting their password
# - But many failures followed by a success can look like password guessing finally worked
#
# We'll check only the top 5 accounts (so output stays readable).
Write-Host ""
Write-Host "========================================"
Write-Host "Checking for 'failed then success' pattern"
Write-Host "========================================"

foreach ($acct in ($failedCounts | Select-Object -First 5)) {
    $name = $acct.Name

    # Get all events for this account and sort by time
    $acctEvents = $parsed |
        Where-Object { $_.AccountName -eq $name } |
        Sort-Object TimeCreated

    # Separate failures and successes
    $fails = $acctEvents | Where-Object { $_.EventId -eq 4625 }
    $success = $acctEvents | Where-Object { $_.EventId -eq 4624 } | Select-Object -First 1

    # Basic rule for learning:
    # If there are 5+ failures AND at least 1 success, flag it as suspicious.
    if ($fails.Count -ge 5 -and $success) {
        Write-Host "POTENTIAL INCIDENT:"
        Write-Host "Account: $name"
        Write-Host "Failed logons: $($fails.Count)"
        Write-Host "First fail time: $($fails[0].TimeCreated)"
        Write-Host "Success time: $($success.TimeCreated)"
        Write-Host "Success logon type: $($success.LogonType)"
        Write-Host "Success source IP: $($success.IpAddress)"
        Write-Host "----------------------------------------"
    }
}

# -----------------------------
# 7) Bonus: show last 10 failed events for quick manual review
# -----------------------------
# This helps beginners see real evidence lines without digging through Event Viewer.
Write-Host ""
Write-Host "Last 10 FAILED logons (4625) for manual review:"
$parsed |
    Where-Object { $_.EventId -eq 4625 } |
    Sort-Object TimeCreated -Descending |
    Select-Object -First 10 TimeCreated, AccountName, LogonType, IpAddress |
    Format-Table -AutoSize
