configuration Win10_ZeroTrust {

  param(
    [string[]] $NodeName = @('localhost'),

    # Gruppen/Identitäten (AD-Gruppen oder lokale Konten)
    [string]   $LocalAdminsGroup            = 'Administrators', 
    [string]   $DenyLocalLogonIdentities    = 'TEKO\ServiceAccounts',
    [string]   $DenyRemoteDesktopIdentities = 'TEKO\ServiceAccounts',

    # BitLocker & RDP
    [bool]     $EnableBitLocker             = $true,
    [bool]     $AllowRdpWithNLA             = $true,

    # WDAC/VBS (Core)
    [bool]     $EnableWDAC_Core             = $true
  )

  #Import-DscResource -ModuleName PSDesiredStateConfiguration
  Import-DscResource -ModuleName PSDscResources
  Import-DscResource -ModuleName NetworkingDsc
  Import-DscResource -ModuleName SecurityPolicyDsc
  Import-DscResource -ModuleName AuditPolicyDsc
  Import-DscResource -ModuleName ComputerManagementDsc

  Node $NodeName {

    # --- BASELINE / Ordner ---
    File SensitiveDir {
      DestinationPath = 'C:\SensitiveData'
      Type            = 'Directory'
      Ensure          = 'Present'
    }

    # Minimale, harte ACL für SensitiveDir (nur Admins + SYSTEM) – per SID, sprachunabhängig
    Script SensitiveDirAcl {
      DependsOn  = '[File]SensitiveDir'
      TestScript = {
        $p = 'C:\SensitiveData'
        if (!(Test-Path $p)) { return $false }
        $acl = Get-Acl $p

        $allowedSids = @('S-1-5-32-544','S-1-5-18')  # Admins, SYSTEM
        # sammle alle eindeutigen SIDs der ACEs
        $aceSids = @()
        foreach ($ace in $acl.Access) {
          $id = $ace.IdentityReference
          if ($id -is [System.Security.Principal.SecurityIdentifier]) {
            $aceSids += $id.Value
          } else {
            # NTAccount → in SID übersetzen (falls möglich)
            try {
              $aceSids += ($id.Translate([System.Security.Principal.SecurityIdentifier])).Value
            } catch { $aceSids += $id.Value } # als Fallback
          }
        }
        $aceSids = $aceSids | Select-Object -Unique

        # TRUE nur, wenn jede ACE zu Admins oder SYSTEM gehört
        return ($aceSids | Where-Object { $_ -notin $allowedSids }).Count -eq 0
      }
      SetScript  = {
        $p = 'C:\SensitiveData'
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $prop    = [System.Security.AccessControl.PropagationFlags]::None
        $full    = [System.Security.AccessControl.FileSystemRights]::FullControl
        $allow   = [System.Security.AccessControl.AccessControlType]::Allow

        $sidAdmins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544') # BUILTIN\Administrators
        $sidSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')    # NT AUTHORITY\SYSTEM

        $acl.AddAccessRule( (New-Object System.Security.AccessControl.FileSystemAccessRule($sidAdmins, $full, $inherit, $prop, $allow)) )
        $acl.AddAccessRule( (New-Object System.Security.AccessControl.FileSystemAccessRule($sidSystem, $full, $inherit, $prop, $allow)) )

        Set-Acl -Path $p -AclObject $acl
      }
      GetScript  = { @{ Result = 'ACL enforced by SID' } }
    }

    # --- EXECUTION POLICY ---
    Script ExecutionPolicyRemoteSigned {
      TestScript = { (Get-ExecutionPolicy) -eq 'RemoteSigned' }
      SetScript  = { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force }
      GetScript  = { @{ Result = (Get-ExecutionPolicy) } }
    }

    # --- OPTIONAL FEATURES / Services ---
    WindowsOptionalFeature DisableTelnetClient {
      Name   = 'TelnetClient'
      Ensure = 'Absent'
    }

    Service DisableRemoteRegistry {
      Name        = 'RemoteRegistry'
      StartupType = 'Disabled'
      State       = 'Stopped'
      Ensure      = 'Present'
    }

    # --- FIREWALL: Default block inbound, allow outbound ---
    FirewallProfile DomainProfile {
      Name                  = 'Domain'
      Enabled               = 'True'
      DefaultInboundAction  = 'Block'
      DefaultOutboundAction = 'Allow'
      NotifyOnListen        = 'False'
    }
    FirewallProfile PrivateProfile {
      Name                  = 'Private'
      Enabled               = 'True'
      DefaultInboundAction  = 'Block'
      DefaultOutboundAction = 'Allow'
    }
    FirewallProfile PublicProfile {
      Name                  = 'Public'
      Enabled               = 'True'
      DefaultInboundAction  = 'Block'
      DefaultOutboundAction = 'Allow'
    }

    # RDP nur mit NLA und auf Domain/Private erlauben
    Registry RdpNla {
      Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
      ValueName = 'UserAuthentication'
      ValueType = 'Dword'
      ValueData = if ($AllowRdpWithNLA) { 1 } else { 0 }
      Ensure    = 'Present'
    }
    Firewall RdpAllowDomainPrivate {
      Name        = 'RDP-In-TCP-3389-DomainPrivate'
      DisplayName = 'RDP Inbound (Domain+Private)'
      Ensure      = if ($AllowRdpWithNLA) { 'Present' } else { 'Absent' }
      Enabled     = if ($AllowRdpWithNLA) { 'True' } else { 'False' }
      Direction   = 'Inbound'
      Action      = 'Allow'
      Protocol    = 'TCP'
      LocalPort   = '3389'
      Profile     = 'Domain,Private'
    }

# --- AUDIT: Anmelden (Success & Failure) ---
Script Audit_Anmelden {
  TestScript = {
    $out = & auditpol /get /subcategory:"Anmelden" 2>$null
    if (-not $out) { return $false }
    $t = ($out | Out-String)
    $succOk = ($t -match '(Erfolg|Success).*(Ein|Enabled)')
    $failOk = ($t -match '(Fehler|Failure).*(Ein|Enabled)')
    return ($succOk -and $failOk)
  }
  SetScript  = { auditpol /set /subcategory:"Anmelden" /success:enable /failure:enable | Out-Null }
  GetScript  = { @{ Result = 'Anmelden Success+Failure' } }
}

# --- AUDIT: Kerberos-Authentifizierungsdienst (Success & Failure) ---
Script Audit_KerbAuth {
  TestScript = {
    $out = & auditpol /get /subcategory:"Kerberos-Authentifizierungsdienst" 2>$null
    if (-not $out) { return $false }
    $t = ($out | Out-String)
    $succOk = ($t -match '(Erfolg|Success).*(Ein|Enabled)')
    $failOk = ($t -match '(Fehler|Failure).*(Ein|Enabled)')
    return ($succOk -and $failOk)
  }
  SetScript  = { auditpol /set /subcategory:"Kerberos-Authentifizierungsdienst" /success:enable /failure:enable | Out-Null }
  GetScript  = { @{ Result = 'Kerberos-Authentifizierungsdienst S+F' } }
}

# --- AUDIT: Ticketvorgänge des Kerberos-Diensts (Success & Failure) ---
Script Audit_KerbTicketOps {
  TestScript = {
    $out = & auditpol /get /subcategory:"Ticketvorgänge des Kerberos-Diensts" 2>$null
    if (-not $out) { return $false }
    $t = ($out | Out-String)
    $succOk = ($t -match '(Erfolg|Success).*(Ein|Enabled)')
    $failOk = ($t -match '(Fehler|Failure).*(Ein|Enabled)')
    return ($succOk -and $failOk)
  }
  SetScript  = { auditpol /set /subcategory:"Ticketvorgänge des Kerberos-Diensts" /success:enable /failure:enable | Out-Null }
  GetScript  = { @{ Result = 'Kerberos Ticketvorgänge S+F' } }
}

# --- AUDIT: Dateisystem (Success & Failure) ---
Script Audit_Dateisystem {
  TestScript = {
    $out = & auditpol /get /subcategory:"Dateisystem" 2>$null
    if (-not $out) { return $false }
    $t = ($out | Out-String)
    $succOk = ($t -match '(Erfolg|Success).*(Ein|Enabled)')
    $failOk = ($t -match '(Fehler|Failure).*(Ein|Enabled)')
    return ($succOk -and $failOk)
  }
  SetScript  = { auditpol /set /subcategory:"Dateisystem" /success:enable /failure:enable | Out-Null }
  GetScript  = { @{ Result = 'Dateisystem S+F' } }
}

# --- AUDIT: Registrierung (Success & Failure) ---
Script Audit_Registrierung {
  TestScript = {
    $out = & auditpol /get /subcategory:"Registrierung" 2>$null
    if (-not $out) { return $false }
    $t = ($out | Out-String)
    $succOk = ($t -match '(Erfolg|Success).*(Ein|Enabled)')
    $failOk = ($t -match '(Fehler|Failure).*(Ein|Enabled)')
    return ($succOk -and $failOk)
  }
  SetScript  = { auditpol /set /subcategory:"Registrierung" /success:enable /failure:enable | Out-Null }
  GetScript  = { @{ Result = 'Registrierung S+F' } }
}

# --- AUDIT: Prozesserstellung (nur Success) ---
Script Audit_Prozesserstellung {
  TestScript = {
    $out = & auditpol /get /subcategory:"Prozesserstellung" 2>$null
    if (-not $out) { return $false }
    $t = ($out | Out-String)
    $succOk = ($t -match '(Erfolg|Success).*(Ein|Enabled)')
    $failOk = ($t -match '(Fehler|Failure).*(Aus|Disabled)')  # optional, wir wollen Failure aus
    return ($succOk -and $failOk)
  }
  SetScript  = { auditpol /set /subcategory:"Prozesserstellung" /success:enable /failure:disable | Out-Null }
  GetScript  = { @{ Result = 'Prozesserstellung Success only' } }
}

    # --- SECURITY OPTIONS & HARDENING ---

    # VBS/Device Guard Grundschalter
    Registry EnableVBS {
      Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
      ValueName = 'EnableVirtualizationBasedSecurity'
      ValueType = 'Dword'
      ValueData = 1
      Ensure    = 'Present'
    }
    Registry RequirePlatformSecurity {
      Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
      ValueName = 'RequirePlatformSecurityFeatures'
      ValueType = 'Dword'
      ValueData = 1
      Ensure    = 'Present'
    }

    # Credential Guard
    Registry LsaCfgFlags {
      Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
      ValueName = 'LsaCfgFlags'
      ValueType = 'Dword'
      ValueData = 1
      Ensure    = 'Present'
    }

    # WDAC/HVCI (Core)
    Registry HVCI {
      Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
      ValueName = 'Enabled'
      ValueType = 'Dword'
      ValueData = if ($EnableWDAC_Core) { 1 } else { 0 }
      Ensure    = 'Present'
    }

    # Enable IsolatedUserMode nur wenn das Feature existiert (sonst noop)
Script EnableIsolatedUserMode {
  TestScript = {
    $f = Get-WindowsOptionalFeature -Online -FeatureName 'IsolatedUserMode' -ErrorAction SilentlyContinue
    if (-not $f) { return $true }              # Feature gibt's nicht → nichts zu tun
    return ($f.State -eq 'Enabled')
  }
  SetScript  = {
    $f = Get-WindowsOptionalFeature -Online -FeatureName 'IsolatedUserMode' -ErrorAction SilentlyContinue
    if ($f) { Enable-WindowsOptionalFeature -Online -FeatureName 'IsolatedUserMode' -All -NoRestart -ErrorAction Stop | Out-Null }
  }
  GetScript  = { @{ Result = 'IsolatedUserMode enabled if available' } }
}

    WindowsOptionalFeature HyperVisorPlatform {
      Name                 = 'HypervisorPlatform'
      Ensure               = 'Present'
    }

    # SMBv1 deaktivieren
    Registry DisableSMB1Server {
      Key='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
      ValueName='SMB1'; ValueType='Dword'; ValueData=0; Ensure='Present'
    }
    Registry DisableSMB1Client {
      Key='HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
      ValueName='Start'; ValueType='Dword'; ValueData=4; Ensure='Present'
    }

    # TLS Härtung – TLS 1.0/1.1 aus, TLS 1.2 an
    Registry TLS10Server { Key='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server';  ValueName='Enabled'; ValueType='Dword'; ValueData=0; Ensure='Present' }
    Registry TLS10Client { Key='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client';  ValueName='Enabled'; ValueType='Dword'; ValueData=0; Ensure='Present' }
    Registry TLS11Server { Key='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server';  ValueName='Enabled'; ValueType='Dword'; ValueData=0; Ensure='Present' }
    Registry TLS11Client { Key='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client';  ValueName='Enabled'; ValueType='Dword'; ValueData=0; Ensure='Present' }
    Registry TLS12Server { Key='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server';  ValueName='Enabled'; ValueType='Dword'; ValueData=1; Ensure='Present' }
    Registry TLS12Client { Key='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client';  ValueName='Enabled'; ValueType='Dword'; ValueData=1; Ensure='Present' }

    # CommandLine in 4688
    Registry AuditProcessCreationIncludeCmdLine {
      Key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
      ValueName='ProcessCreationIncludeCmdLine_Enabled'; ValueType='Dword'; ValueData=1; Ensure='Present'
    }

    # LSASS als geschützter Prozess
    Registry RunAsPPL {
      Key='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
      ValueName='RunAsPPL'; ValueType='Dword'; ValueData=1; Ensure='Present'
    }

    # Nur NTLMv2
    Registry LmCompatibilityLevel {
      Key='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
      ValueName='LmCompatibilityLevel'; ValueType='Dword'; ValueData=5; Ensure='Present'
    }

    # Unsichere Gastanmeldung SMB deaktivieren
    Registry AllowInsecureGuestAuth {
      Key='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
      ValueName='AllowInsecureGuestAuth'; ValueType='Dword'; ValueData=0; Ensure='Present'
    }

    # RDP Sicherheitslayer = TLS
    Registry RDPSecurityLayer {
      Key='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
      ValueName='SecurityLayer'; ValueType='Dword'; ValueData=2; Ensure='Present'
    }

    # --- USER RIGHTS ASSIGNMENTS (Token-Namen, nicht lokalisiert) ---
    UserRightsAssignment DenyLogOnLocally {
      Policy   = 'Deny_log_on_locally'
      Identity = $DenyLocalLogonIdentities
      Ensure   = 'Present'
    }
    UserRightsAssignment DenyLogOnViaRDP {
      Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
      Identity = $DenyRemoteDesktopIdentities
      Ensure   = 'Present'
    }
    UserRightsAssignment LogOnAsService {
      Policy   = 'Log_on_as_a_service'
      Identity = $LocalAdminsGroup
      Ensure   = 'Present'
    }

    # --- DEFENDER / LOGGING ---
    Registry EnableMAPS { Key='HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet'; ValueName='SpynetReporting'; ValueType='Dword'; ValueData=2; Ensure='Present' }
    Registry SubmitSamplesConsent { Key='HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet'; ValueName='SubmitSamplesConsent'; ValueType='Dword'; ValueData=2; Ensure='Present'; Force=$true }
    Registry PUAProtection { Key='HKLM:\SOFTWARE\Microsoft\Windows Defender'; ValueName='PUAProtection'; ValueType='Dword'; ValueData=1; Ensure='Present' }

    Script BitLockerOS {
  TestScript = {
    if (-not $using:EnableBitLocker) { return $true }
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if (-not $tpm -or -not $tpm.TpmPresent) { return $true }  # kein TPM → überspringen )
    $os = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
    if (-not $os) { return $false }
    return ($os.ProtectionStatus -eq 'On')
  }
  SetScript  = {
    if (-not $using:EnableBitLocker) { return }
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if (-not $tpm -or -not $tpm.TpmPresent) {
      Write-Verbose 'BitLocker übersprungen: Kein TPM vorhanden.'
      return
    }
    Enable-BitLocker -MountPoint 'C:' -UsedSpaceOnly -RecoveryPasswordProtector -ErrorAction Stop
  }
  GetScript  = { @{ Result = 'BitLocker enforced if TPM present' } }
}


    Service WinDefender {
      Name        = 'WinDefend'
      StartupType = 'Automatic'
      State       = 'Running'
      Ensure      = 'Present'
    }

    Registry SecurityLogMaxSize {
      Key='HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'
      ValueName='MaxSize'; ValueType='Dword'; ValueData=1966080; Ensure='Present'; Force=$true
    }
  } # end Node
}
