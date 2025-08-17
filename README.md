This script fetches BitLocker recovery keys for a list of Entra device OBJECT IDs and upload to Azure Key Vault.

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
