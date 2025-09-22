# Win10_ZeroTrust DSC-Konfiguration

## Überblick

Die Datei [`Win10_ZeroTrust.ps1`](Win10_ZeroTrust.ps1) enthält eine PowerShell Desired State Configuration (DSC),
die einen gehärteten "Zero Trust"-Baseline-Zustand für Windows-10-Clients herstellt. Die Konfiguration legt
einen sensitiven Datenordner mit restriktiven NTFS-Berechtigungen an, verhärtet Firewall- und RDP-Einstellungen,
aktiviert umfassende Überwachungsrichtlinien, schaltet optionale Features wie Credential Guard/WDAC ein, deaktiviert
veraltete Protokolle (SMBv1, TLS 1.0/1.1) und erzwingt Sicherheits- sowie Defender-Richtlinien.

## Enthaltene Sicherheitsmassnahmen

- **Baseline & Datei­schutz**: Erstellt `C:\SensitiveData` und setzt ACLs ausschliesslich auf Administratoren und SYSTEM.
- **PowerShell & Dienste**: Erzwingt die Execution Policy `RemoteSigned`, deinstalliert den Telnet-Client und deaktiviert
  den Remote-Registry-Dienst.
- **Netzwerk & RDP**: Erzwingt blockierende Standard-Firewallprofile, lässt optional RDP nur mit Network Level
  Authentication (NLA) und Domain/Private-Profil zu und erzwingt TLS-geschützte RDP-Verbindungen.
- **Auditing**: Aktiviert detaillierte Ereignissammlungen für Anmelde-, Kerberos-, Datei-/Registry-Zugriffe und die
  Prozess­erstellung (inklusive Befehlszeilenaufzeichnung).
- **Virtualization Based Security**: Aktiviert Credential Guard, HVCI/WDAC (optional per Parameter), Isolated User Mode
  sowie das Hypervisor Platform Feature.
- **Protokoll- & Registry-Härtung**: Deaktiviert SMBv1, schaltet TLS 1.0/1.1 aus und erzwingt TLS 1.2, schützt LSASS als
  geschützten Prozess, erzwingt NTLMv2 und blockiert unsichere SMB-Gastanmeldungen.
- **Benutzerrechte & Defender**: Setzt An-/Abmeldebeschränkungen, konfiguriert Windows Defender MAPS/PUA, startet den
  Defender-Dienst und vergrössert das Security-Eventlog. Optional wird BitLocker (TPM-abhängig) aktiviert.

> **Hinweis:** Einige Massnahmen (z. B. BitLocker, VBS/WDAC) setzen geeignete Hardware-Voraussetzungen (TPM, UEFI,
> Virtualisierungs­unterstützung, Secure Boot) voraus und können Neustarts auslösen.

## Voraussetzungen

### Unterstützte Plattformen

- Windows 10
- PowerShell 5.1
- Lokale Administratorrechte für die Ausführung der Konfiguration.

### Allgemeine Voraussetzungen

- WinRM muss für Remote-DSC-Pushs aktiv sein (`Enable-PSRemoting -Force`).
- Der NuGet-Provider für die PowerShell-Gallery muss einmalig bestätigt werden (`Install-PackageProvider -Name NuGet`).

### Benötigte PowerShell-Module

Folgende Module werden von der Konfiguration importiert und müssen auf dem Verwaltungs- **und** Zielsystem vorhanden sein
(Versionen ≥ die jeweils aktuelle Galerie-Version werden empfohlen):

```powershell
Install-Module -Name PSDscResources,NetworkingDsc,SecurityPolicyDsc,AuditPolicyDsc,ComputerManagementDsc \
  -Repository PSGallery -Scope AllUsers
```

> In abgeschotteten Umgebungen können die Module aus der PowerShell-Gallery auf dem Management-System heruntergeladen und
> anschliessend in `C:\Program Files\WindowsPowerShell\Modules` der Clients kopiert werden.

## Server-seitige Vorbereitung (Management-Server)

1. **Repository klonen** (oder Skript kopieren) auf dem DCS Server.
2. **Module installieren** (siehe oben) und sicherstellen, dass `PSGallery` als vertrauenswürdig markiert ist
   (`Set-PSRepository -Name PSGallery -InstallationPolicy Trusted`).
3. **Konfigurationsfunktion laden**:
   ```powershell
   .\Win10_ZeroTrust.ps1
   ```
4. **MOF-Dateien erzeugen** – Beispiel für zwei Clients:
   ```powershell
   $params = {
     Win10_ZeroTrust -NodeName 'PC1','PC2' -OutputPath '.\MOF' \
       -LocalAdminsGroup 'Administrators' \
       -DenyLocalLogonIdentities 'TEKO\ServiceAccounts' \
       -DenyRemoteDesktopIdentities 'TEKO\ServiceAccounts' \
       -EnableBitLocker $true -AllowRdpWithNLA $true -EnableWDAC_Core $true
   }
   & $params
   ```
   Pro Zielsystem sollte nun eine kompilierte `.mof`-Datei bereit sein.

## Client-seitige Vorbereitung (verwaltete Windows-Geräte)

1. Sicherstellen, dass die erforderlichen Module installiert oder bereitgestellt sind.
2. WinRM/DSC-Kommunikation erlauben (Firewall-Ausnahme für `WINRM-HTTP-IN` und ggf. TrustedHosts setzen).
3. Prüfen, ob Hardwarevoraussetzungen erfüllt sind:
   - TPM 2.0 vorhanden und aktiviert (für BitLocker).
   - UEFI, Secure Boot und Virtualisierung (Intel VT-x/AMD-V) aktiviert (für VBS, Credential Guard, HVCI).
4. Vorhandene BitLocker-/WDAC-/Firewall-Policies dokumentieren, da sie durch DSC überschrieben werden können.

## Ausführung (Push-Szenario)

1. Auf dem Management-System (oder direkt auf dem Client) die Konfiguration ausführen:
   ```powershell
   . .\Win10_ZeroTrust.ps1
   Win10_ZeroTrust -NodeName 'PC1' -OutputPath '.\MOF'
   ```
2. Die erzeugte MOF anwenden:
   ```powershell
   Start-DscConfiguration -Path '.\MOF' -Wait -Verbose -Force
   ```
3. Fortschritt überwachen:
   ```powershell
   Get-DscConfigurationStatus
   Get-DscConfiguration
   Test-DscConfiguration
   ```
4. Eventuelle Neustarts zulassen (`-Force`) und nach Abschluss die Ereignisprotokolle auf Fehler prüfen.

## Parameterübersicht

| Parameter                     | Standardwert           | Beschreibung                                                  |
| ----------------------------- | ---------------------- | ------------------------------------------------------------- |
| `NodeName`                    | `localhost`            | Zielcomputer(e) für die MOF-Erzeugung.                        |
| `LocalAdminsGroup`            | `Administrators`       | Konto/Gruppe, die das Recht "Als Dienst anmelden" erhält.     |
| `DenyLocalLogonIdentities`    | `TEKO\ServiceAccounts` | Identität(en), denen die lokale Anmeldung verweigert wird.    |
| `DenyRemoteDesktopIdentities` | `TEKO\ServiceAccounts` | Identität(en), denen RDP-Anmeldung verweigert wird.           |
| `EnableBitLocker`             | `$true`                | Aktiviert BitLocker auf Laufwerk C:, sofern TPM verfügbar.    |
| `AllowRdpWithNLA`             | `$true`                | Ermöglicht RDP nur mit NLA und Domain/Private-Firewallprofil. |
| `EnableWDAC_Core`             | `$true`                | Aktiviert HVCI/WDAC (setzt VBS/Virtualisierung voraus).       |

Die Parameter können bei der MOF-Erstellung überschrieben werden, um z. B. BitLocker zu deaktivieren oder andere Gruppen zu
verwenden.

## Fehlerbehebung & Betrieb

- **Modulversionen fehlen**: Prüfen, ob alle DSC-Module auf Client und Server identisch vorhanden sind (`Get-DscResource`).
- **Hardware fehlt**: Falls TPM/VBS-Hardware nicht vorhanden ist, bleiben die entsprechenden Ressourcensets im Testmodus auf
  `true` (BitLocker wird übersprungen, Features bleiben deaktiviert).
- **Konflikte mit GPOs**: Gruppenrichtlinien können DSC-Einstellungen überschreiben; sicherstellen, dass keine konkurrierenden
  Richtlinien aktiv sind.
- **Rollbacks**: Zum Entfernen der Konfiguration `Remove-DscConfigurationDocument -Stage Current,Pending` und die gesetzten
  Einstellungen manuell anpassen.
