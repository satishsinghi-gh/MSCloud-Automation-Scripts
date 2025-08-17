<# 
Author: Satish Singhi
Date: 08/15/2025

Fetch BitLocker recovery keys for a list of Entra device OBJECT IDs and upload to Azure Key Vault.

Highlights:

Fetches latest Bitlocker key per device based on an input file containing Device Object IDs
Uploads the keys in [DeviceName--RecoveryKey] format to Azure KeyVault
Writes CSV & Log file output with Date Suffix (_MM-DD)
Masks actual recovery key in Logs
Records following items in output CSV - DeviceName, ObjectID, ExecutionDate, KeyID, Status
Logic to handle file lock scenarios and to append a suffix if file name already exists in output path

Required Permissions & Modules:

Manually install required modules if not already installed:
  Install-Module Microsoft.Graph -Scope CurrentUser -Force - AllowClobber
  Install-Module Az.Accounts     -Scope CurrentUser -Force - AllowClobber
  Install-Module Az.KeyVault     -Scope CurrentUser -Force - AllowClobber

Delegated Graph scopes: BitLockerKey.Read.All, Device.Read.All
Key Vault access: permission to set secrets.

#>

# =========================
# CONFIG — Set values
# =========================
$TenantId       = "Your TenantID"  # Entra tenant GUID
$ClientId       = "Your ClientID"  # Public client (no secret) app ID
$SubscriptionId = "Your Sub ID"  # Subscription with the Key Vault
$VaultName      = "Your Key Vault Name"                        # Target Key Vault name
$InputPath      = "Input File Path"      # One OBJECT ID per line
$OutputCsv      = "Output CSV path"       # Base CSV path (suffix added automatically)

# Secret name pattern (DeviceName--RecoveryKey)
# Safer alternative: "{deviceName}--{shortId}" (optional, not used)
$SecretNameFormat = "{deviceName}--{key}"
$SecretContentType = "BitLocker Recovery"

# =========================
# Runtime Settings
# =========================
$ErrorActionPreference = "Stop"

# =========================
# Helpers  - {deviceName}--{key} | (shortID) optional to mask Key in KV | Input data processing (Object ID's) | 
# =========================
function ConvertTo-SecretNameSafe {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Name)
  $safe = ($Name -replace '[^0-9A-Za-z-]', '-').Trim('-')
  if ([string]::IsNullOrWhiteSpace($safe)) { $safe = "unnamed" }
  if ($safe.Length -gt 127) { $safe = $safe.Substring(0,127) }
  return $safe
}

function Format-SecretName {
  # Enforces 127-char cap while keeping the right side (recovery key) intact when possible
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Format,
    [Parameter(Mandatory)][string]$Id,          # key id
    [string]$DeviceId = "",
    [string]$DeviceName = "",
    [string]$Key = ""                           # recovery key
  )
  $shortId = if ($Id -and $Id.Length -ge 8) { $Id.Substring(0,8) } else { $Id }
  $name = $Format.Replace('{id}', $Id).
                  Replace('{shortId}', $shortId).
                  Replace('{deviceId}', $DeviceId).
                  Replace('{deviceName}', $DeviceName).
                  Replace('{key}', $Key)

  $name = ConvertTo-SecretNameSafe $name
  if ($name.Length -gt 127) {
    $parts = $name -split '--', 2
    if ($parts.Count -eq 2) {
      $left, $right = $parts[0], $parts[1]
      $maxLeft = 127 - 2 - $right.Length
      if ($maxLeft -lt 1) { $maxLeft = 1 }
      if ($left.Length -gt $maxLeft) { $left = $left.Substring(0,$maxLeft) }
      $name = ConvertTo-SecretNameSafe ("$left--$right")
    } else {
      $name = $name.Substring(0,127)
    }
  }
  return $name
}

function Read-ObjectIdsFromFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) { throw "Input file not found: $Path" }

  $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
  $raw = $raw -replace '^\uFEFF',''  # strip UTF-8 BOM if present
  $lines = $raw -split "`r?`n"
  $ids = foreach ($line in $lines) {
    $t = ($line ?? '').Trim()
    if ($t -and -not $t.StartsWith('#')) { $t }
  }
  return $ids
}

function Try-Resolve-Device {
  <#
    Input: Entra device OBJECT ID.
    Output: @{ ObjectId = <guid>; DeviceId = <guid>; DisplayName = <string> } or $null
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ObjectId)

  try {
    $d = Get-MgDevice -DeviceId $ObjectId -ErrorAction Stop
    return @{
      ObjectId    = $d.Id
      DeviceId    = $d.DeviceId
      DisplayName = ($d.DisplayName ?? $d.Id)
    }
  } catch {
    return $null
  }
}

function Get-UniquePath {
  <#
    If $Path exists, returns a new path with -Update / -Update1 / -Update2 ... before extension.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  $dir  = Split-Path -Parent $Path
  $file = [System.IO.Path]::GetFileNameWithoutExtension($Path)
  $ext  = [System.IO.Path]::GetExtension($Path)

  if (-not (Test-Path -LiteralPath $Path)) { return $Path }

  $i = 0
  while ($true) {
    $suffix = if ($i -eq 0) { "-Update" } else { "-Update$($i)" }
    $candidate = Join-Path $dir ($file + $suffix + $ext)
    if (-not (Test-Path -LiteralPath $candidate)) { return $candidate }
    $i++
  }
}

function New-OutputPaths {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$BaseCsvPath)

  $dir  = Split-Path -Parent $BaseCsvPath
  $base = [System.IO.Path]::GetFileNameWithoutExtension($BaseCsvPath)
  $ext  = [System.IO.Path]::GetExtension($BaseCsvPath)

  $csvSuffix = (Get-Date).ToString("MM-dd")       # e.g., 08-15
  $logSuffix = (Get-Date).ToString("MM-dd-yy")    # filename-safe version of mm/dd/yy

  $csvCandidate = Join-Path $dir "$base`_$csvSuffix$ext"
  $logCandidate = Join-Path $dir "$base`_$logSuffix.log"

  $csvPath = Get-UniquePath -Path $csvCandidate
  $logPath = Get-UniquePath -Path $logCandidate

  return @{ CsvPath = $csvPath; LogPath = $logPath }
}

# Log handling
function Write-Log {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Message,
    [Parameter(Mandatory)][string]$Path
  )
  # Convert truly empty to a single space so binding always succeeds
  if ([string]::IsNullOrEmpty($Message)) { $Message = " " }

  $ts = Get-Date -Format "HH:mm:ss"
  $line = "[$ts] $Message"

  $maxTries = 5
  for ($t=1; $t -le $maxTries; $t++) {
    try {
      $d = Split-Path -Parent $Path
      if ($d -and -not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }

      $fs = [System.IO.File]::Open($Path,
              [System.IO.FileMode]::Append,
              [System.IO.FileAccess]::Write,
              [System.IO.FileShare]::ReadWrite)
      $sw = New-Object System.IO.StreamWriter($fs)
      $sw.WriteLine($line)
      $sw.Flush()
      $sw.Dispose()
      $fs.Dispose()
      break
    } catch {
      if ($t -eq $maxTries) { throw $_ }
      Start-Sleep -Milliseconds (150 * $t)
    }
  }
}

# Log helper to mask key value
function Echo-Log {
  param([string]$Message, [string]$Path, [string]$Color = "Gray")
  if ([string]::IsNullOrEmpty($Message)) { $Message = " " }  # prevent empty binding issue
  Write-Host $Message -ForegroundColor $Color
  Write-Log -Message $Message -Path $Path
}

# =========================
# Output Path
# =========================
$paths = New-OutputPaths -BaseCsvPath $OutputCsv
$OutputCsvFinal = $paths.CsvPath
$LogFile        = $paths.LogPath

$ExecutionDateStr = Get-Date -Format "MM/dd/yy"  # for CSV rows

$csvDir = Split-Path -Parent $OutputCsvFinal
if ($csvDir -and -not (Test-Path -LiteralPath $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

Write-Log -Message "----- Run start (ExecutionDate: $ExecutionDateStr) -----" -Path $LogFile

# =========================
# Connect & Authenticate
# =========================

Echo-Log "Connecting to Microsoft Graph..." $LogFile "Cyan"

Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Scopes @("BitLockerKey.Read.All","Device.Read.All") | Out-Null
$ctx = Get-MgContext
Echo-Log "Graph: Connected as $($ctx.Account) to $($ctx.TenantId)" $LogFile "Green"

Echo-Log "Connecting to Azure and selecting subscription..." $LogFile "Cyan"
Connect-AzAccount -Tenant $TenantId | Out-Null
Set-AzContext -Tenant $TenantId -Subscription $SubscriptionId | Out-Null
Echo-Log "Azure: Context set to subscription $SubscriptionId." $LogFile "Green"

# =========================
# MAIN
# =========================
$objectIds = Read-ObjectIdsFromFile -Path $InputPath
if (-not $objectIds -or $objectIds.Count -eq 0) { 
  Echo-Log "No device OBJECT IDs found in $InputPath" $LogFile "Red"
  throw "No device OBJECT IDs found in $InputPath"
}

$rows = New-Object System.Collections.Generic.List[object]
$idx = 0; $total = $objectIds.Count

foreach ($objId in $objectIds) {
  $idx++
  Echo-Log "[$idx/$total] Processing objectId: $objId" $LogFile "Yellow"

  $deviceName = ""
  $deviceId   = ""
  $actualObjectId = $objId

  try {
    # 1) Resolve to deviceId + name
    $info = Try-Resolve-Device -ObjectId $objId
    if (-not $info) {
      Echo-Log "   Error: Device object not found." $LogFile "Red"
      $rows.Add([pscustomobject]@{
        DeviceName     = ""
        ObjectId       = $objId
        RecoveryKeyId  = ""
        ExecutionDate  = $ExecutionDateStr
        Status         = "Failed"
      })
      continue
    }

    $deviceName     = $info.DisplayName
    $deviceId       = $info.DeviceId
    $actualObjectId = $info.ObjectId

    Echo-Log "   Device name: $deviceName" $LogFile
    Echo-Log "   deviceId   : $deviceId"   $LogFile

    if ([string]::IsNullOrWhiteSpace($deviceId)) { throw "Resolved device has no deviceId; cannot query BitLocker keys." }

    # 2) Get newest BitLocker key
    $keyRec = Get-MgInformationProtectionBitlockerRecoveryKey -Filter "deviceId eq '$deviceId'" -All |
              Sort-Object createdDateTime -Descending | Select-Object -First 1

    if (-not $keyRec) {
      Echo-Log "  Warning:  No BitLocker recovery keys found." $LogFile "Yellow"
      $rows.Add([pscustomobject]@{
        DeviceName     = $deviceName
        ObjectId       = $actualObjectId
        RecoveryKeyId  = ""
        ExecutionDate  = $ExecutionDateStr
        Status         = "NotFound"
      })
      continue
    }

    $recoveryKeyId = $keyRec.Id
    Echo-Log "   Latest KeyId: $recoveryKeyId (created $($keyRec.createdDateTime))" $LogFile

    # 3) Fetch the recovery key string (Do NOT print actual value)
    $full = Get-MgInformationProtectionBitlockerRecoveryKey -BitlockerRecoveryKeyId $recoveryKeyId -Property "key"
    $recoveryKey = $full.Key
    if ([string]::IsNullOrWhiteSpace($recoveryKey)) { throw "Recovery key property is empty." }
    Echo-Log "   Recovery key retrieved: RecoveryKey" $LogFile  # masked

    # 4) Build secret (real + masked for output)
    $secretNameReal = Format-SecretName -Format $SecretNameFormat `
                                        -Id $recoveryKeyId `
                                        -DeviceId $deviceId `
                                        -DeviceName $deviceName `
                                        -Key $recoveryKey
    $secretNameMasked = Format-SecretName -Format $SecretNameFormat `
                                          -Id $recoveryKeyId `
                                          -DeviceId $deviceId `
                                          -DeviceName $deviceName `
                                          -Key "RecoveryKey"

    Echo-Log "   Secret name: $secretNameMasked" $LogFile  # masked display only
    Echo-Log "   Uploading to Key Vault '$VaultName'..." $LogFile

    # 5) Upload secret
    $secure = ConvertTo-SecureString -String $recoveryKey -AsPlainText -Force
    $null = Set-AzKeyVaultSecret -VaultName $VaultName `
                                 -Name $secretNameReal `
                                 -SecretValue $secure `
                                 -ContentType $SecretContentType `
                                 -ErrorAction Stop

    Echo-Log "   ✅ Uploaded." $LogFile "Green"

    # CSV Rows
    $rows.Add([pscustomobject]@{
      DeviceName     = $deviceName
      ObjectId       = $actualObjectId
      RecoveryKeyId  = $recoveryKeyId
      ExecutionDate  = $ExecutionDateStr
      Status         = "Uploaded"
    })
  }
  catch {
    $err = $_.Exception.Message
    Echo-Log "   Error: Error: $err" $LogFile "Red"
    $rows.Add([pscustomobject]@{
      DeviceName     = $deviceName
      ObjectId       = $actualObjectId
      RecoveryKeyId  = ""
      ExecutionDate  = $ExecutionDateStr
      Status         = "Failed"
    })
  }
}

# =========================
# OUTPUT CSV + LOG FOOTER
# =========================
$rows | Export-Csv -LiteralPath $OutputCsvFinal -NoTypeInformation -Encoding UTF8
Echo-Log "" $LogFile
Echo-Log "CSV saved to: $OutputCsvFinal" $LogFile "Cyan"
Echo-Log "Log saved to: $LogFile" $LogFile "Cyan"
Echo-Log "----- Run complete -----" $LogFile
