# Drift Simulation


## Objective
The purpose of this simulation is to intentionally degrade the security posture of a DISA STIG-compliant Windows 11 endpoint to validate the `drift_analyzer.py` detection pipeline.

# Baseline state
* OS - Windows 11 Enterprise
* Profile - Factory default / OOBE
* Context - The baseline scan natively contains numerous DISA STIG failures due to Windows default configuration. The goal of the drift engine is to ignore this failures and only focus on new drifts.


## Execution: Induced Regressions
To trigger the automated drift detection, the following configuration changes were manually introduced.

### 1. Account Security Degradation (CAT I)
Enabled the built-in Guest account to simulate an unauthenticated access vector.
* Method: `lusrmgr.msc` -> Guest -> Uncheck "Account is disabled"
* Expected Detection: Anonymous/Guest access control failures flagged as NEW regressions.

### 2. Audit Logging Evasion (CAT II)
Disabled critical telemetry required by the Security Operations Center (SOC) to track threat actor movement.
* Method: Local Security Policy (`secpol.msc`)
* Changes: Audit Logon Events -> No Auditing
  * Audit Directory Service Access -> Failure Only
* Expected Detection:** Event logging and auditing policy regressions.

### 3. Attack Surface Expansion (CAT II)
Enabled Remote Desktop Protocol (RDP) and disabled Network Level Authentication (NLA), exposing the login prompt to the network.
* Method: PowerShell
* Commands Executed:**
  ```powershell
  Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
  Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -value 0
  Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
