rule rule_AutoRDPwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AutoRDPwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoRDPwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AutoRDPwn_offensive_tool_keyword = /\s\-Reverse\s\-IPAddress\s.{0,100}\s\-Port\s/ nocase ascii wide
                        $string2_AutoRDPwn_offensive_tool_keyword = /\s\-TaskName\s.{0,100}AutoRDPwn/ nocase ascii wide
                        $string3_AutoRDPwn_offensive_tool_keyword = /\/AutoBypass\.ps1/ nocase ascii wide
                        $string4_AutoRDPwn_offensive_tool_keyword = /\/autordpwn\.php/ nocase ascii wide
                        $string5_AutoRDPwn_offensive_tool_keyword = "/AutoRDPwn/master/" nocase ascii wide
                        $string6_AutoRDPwn_offensive_tool_keyword = "656761faa342911d398af21edaf085f978ffa53a6bf3919763dfa82aba2301f1" nocase ascii wide
                        $string7_AutoRDPwn_offensive_tool_keyword = "86c1800ab9c9f90d5d5ce81a1f1daae1446cdb98686c59b4d5336216725bfb8e" nocase ascii wide
                        $string8_AutoRDPwn_offensive_tool_keyword = "97b8d3a33ca3a06d24553a8ea8a5a89520ebe15655fa338b2f7c7c8883ae38da" nocase ascii wide
                        $string9_AutoRDPwn_offensive_tool_keyword = "Add-ServiceDacl" nocase ascii wide
                        $string10_AutoRDPwn_offensive_tool_keyword = /AutoBypass\.ps1/ nocase ascii wide
                        $string11_AutoRDPwn_offensive_tool_keyword = "AutoRDPwn" nocase ascii wide
                        $string12_AutoRDPwn_offensive_tool_keyword = /AutoRDPwn\.ps1/ nocase ascii wide
                        $string13_AutoRDPwn_offensive_tool_keyword = "Bypass-UAC" nocase ascii wide
                        $string14_AutoRDPwn_offensive_tool_keyword = "c7874c257949a3c09dcb16f17c6fdb5ea0c5adb143004e7cc4adc63eb3ed785c" nocase ascii wide
                        $string15_AutoRDPwn_offensive_tool_keyword = /Chachi\-Enumerator\.ps1/ nocase ascii wide
                        $string16_AutoRDPwn_offensive_tool_keyword = /Check\-LocalAdminHash\.ps1/ nocase ascii wide
                        $string17_AutoRDPwn_offensive_tool_keyword = "d366383b6e737fd3af2acc5ebc9f209a2c49209b7b444af3c7fe1d39e1775894" nocase ascii wide
                        $string18_AutoRDPwn_offensive_tool_keyword = "DownloadAndExtractFromRemoteRegistry" nocase ascii wide
                        $string19_AutoRDPwn_offensive_tool_keyword = "Get-CredPersist" nocase ascii wide
                        $string20_AutoRDPwn_offensive_tool_keyword = "Get-DecodedPassword" nocase ascii wide
                        $string21_AutoRDPwn_offensive_tool_keyword = "Get-DecryptedCpassword" nocase ascii wide
                        $string22_AutoRDPwn_offensive_tool_keyword = "Get-DecryptedPassword" nocase ascii wide
                        $string23_AutoRDPwn_offensive_tool_keyword = "Get-DiscosdurosGet-PSDrive" nocase ascii wide
                        $string24_AutoRDPwn_offensive_tool_keyword = "Get-LsaRunAsPPLStatus" nocase ascii wide
                        $string25_AutoRDPwn_offensive_tool_keyword = /Get\-NTLM\.ps1/ nocase ascii wide
                        $string26_AutoRDPwn_offensive_tool_keyword = "Get-UnattendSensitiveData" nocase ascii wide
                        $string27_AutoRDPwn_offensive_tool_keyword = "Get-UserPrivileges" nocase ascii wide
                        $string28_AutoRDPwn_offensive_tool_keyword = "Get-Wlan-Keys" nocase ascii wide
                        $string29_AutoRDPwn_offensive_tool_keyword = "Invoke-ApplicationsOnStartupCheck" nocase ascii wide
                        $string30_AutoRDPwn_offensive_tool_keyword = "Invoke-CredentialFilesCheck" nocase ascii wide
                        $string31_AutoRDPwn_offensive_tool_keyword = "Invoke-DllHijackingCheck" nocase ascii wide
                        $string32_AutoRDPwn_offensive_tool_keyword = "Invoke-GPPPasswordCheck" nocase ascii wide
                        $string33_AutoRDPwn_offensive_tool_keyword = "Invoke-HijackableDllsCheck" nocase ascii wide
                        $string34_AutoRDPwn_offensive_tool_keyword = "Invoke-InstalledServicesCheck" nocase ascii wide
                        $string35_AutoRDPwn_offensive_tool_keyword = "Invoke-Keylogger" nocase ascii wide
                        $string36_AutoRDPwn_offensive_tool_keyword = "Invoke-LapsCheck" nocase ascii wide
                        $string37_AutoRDPwn_offensive_tool_keyword = "Invoke-LocalAdminGroupCheck" nocase ascii wide
                        $string38_AutoRDPwn_offensive_tool_keyword = "Invoke-LsaProtectionsCheck" nocase ascii wide
                        $string39_AutoRDPwn_offensive_tool_keyword = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
                        $string40_AutoRDPwn_offensive_tool_keyword = "Invoke-Phant0m" nocase ascii wide
                        $string41_AutoRDPwn_offensive_tool_keyword = /Invoke\-Phant0m\.ps1/ nocase ascii wide
                        $string42_AutoRDPwn_offensive_tool_keyword = /Invoke\-PipeShell\.ps1/ nocase ascii wide
                        $string43_AutoRDPwn_offensive_tool_keyword = "Invoke-Portscan" nocase ascii wide
                        $string44_AutoRDPwn_offensive_tool_keyword = /Invoke\-Portscan\.ps1/ nocase ascii wide
                        $string45_AutoRDPwn_offensive_tool_keyword = "Invoke-PowerShellTcp" nocase ascii wide
                        $string46_AutoRDPwn_offensive_tool_keyword = /Invoke\-PowerShellTcp\.ps1/ nocase ascii wide
                        $string47_AutoRDPwn_offensive_tool_keyword = "Invoke-PrivescCheck" nocase ascii wide
                        $string48_AutoRDPwn_offensive_tool_keyword = /Invoke\-PrivescCheck\.ps1/ nocase ascii wide
                        $string49_AutoRDPwn_offensive_tool_keyword = /Invoke\-PSexec\.ps1/ nocase ascii wide
                        $string50_AutoRDPwn_offensive_tool_keyword = /Invoke\-RDPwrap\.ps1/ nocase ascii wide
                        $string51_AutoRDPwn_offensive_tool_keyword = "Invoke-RegistryAlwaysInstallElevatedCheck" nocase ascii wide
                        $string52_AutoRDPwn_offensive_tool_keyword = /Invoke\-RevShellServer\.ps1/ nocase ascii wide
                        $string53_AutoRDPwn_offensive_tool_keyword = /Invoke\-RunAs\.ps1/ nocase ascii wide
                        $string54_AutoRDPwn_offensive_tool_keyword = "Invoke-SamBackupFilesCheck" nocase ascii wide
                        $string55_AutoRDPwn_offensive_tool_keyword = "Invoke-ScheduledTasksCheck" nocase ascii wide
                        $string56_AutoRDPwn_offensive_tool_keyword = "Invoke-ServicesImagePermissionsCheck" nocase ascii wide
                        $string57_AutoRDPwn_offensive_tool_keyword = "Invoke-ServicesPermissionsCheck" nocase ascii wide
                        $string58_AutoRDPwn_offensive_tool_keyword = "Invoke-ServicesPermissionsRegistryCheck" nocase ascii wide
                        $string59_AutoRDPwn_offensive_tool_keyword = "Invoke-ServicesUnquotedPathCheck" nocase ascii wide
                        $string60_AutoRDPwn_offensive_tool_keyword = "Invoke-SessionGopher" nocase ascii wide
                        $string61_AutoRDPwn_offensive_tool_keyword = /Invoke\-SharpRDP\.ps1/ nocase ascii wide
                        $string62_AutoRDPwn_offensive_tool_keyword = /Invoke\-SharpWeb\.ps1/ nocase ascii wide
                        $string63_AutoRDPwn_offensive_tool_keyword = "Invoke-SMBExec" nocase ascii wide
                        $string64_AutoRDPwn_offensive_tool_keyword = /Invoke\-SMBExec\.ps1/ nocase ascii wide
                        $string65_AutoRDPwn_offensive_tool_keyword = "Invoke-SystemStartupHistoryCheck" nocase ascii wide
                        $string66_AutoRDPwn_offensive_tool_keyword = "Invoke-UacCheck" nocase ascii wide
                        $string67_AutoRDPwn_offensive_tool_keyword = "Invoke-UnattendFilesCheck" nocase ascii wide
                        $string68_AutoRDPwn_offensive_tool_keyword = "Invoke-UserPrivilegesCheck" nocase ascii wide
                        $string69_AutoRDPwn_offensive_tool_keyword = "Invoke-VaultCredCheck" nocase ascii wide
                        $string70_AutoRDPwn_offensive_tool_keyword = /Invoke\-VNCServer\.ps1/ nocase ascii wide
                        $string71_AutoRDPwn_offensive_tool_keyword = /Invoke\-VNCViewer\.ps1/ nocase ascii wide
                        $string72_AutoRDPwn_offensive_tool_keyword = /Invoke\-WebRev\.ps1/ nocase ascii wide
                        $string73_AutoRDPwn_offensive_tool_keyword = "Invoke-WinlogonCheck" nocase ascii wide
                        $string74_AutoRDPwn_offensive_tool_keyword = "Invoke-WMIExec" nocase ascii wide
                        $string75_AutoRDPwn_offensive_tool_keyword = /ListAllUsers\.ps1/ nocase ascii wide
                        $string76_AutoRDPwn_offensive_tool_keyword = /net\slocalgroup\s.{0,100}\sAutoRDPwn\s\/add/ nocase ascii wide
                        $string77_AutoRDPwn_offensive_tool_keyword = "net user AutoRDPwn" nocase ascii wide
                        $string78_AutoRDPwn_offensive_tool_keyword = "PortScan-Alive" nocase ascii wide
                        $string79_AutoRDPwn_offensive_tool_keyword = "Portscan-Port" nocase ascii wide
                        $string80_AutoRDPwn_offensive_tool_keyword = /RDP\-Caching\.ps1/ nocase ascii wide
                        $string81_AutoRDPwn_offensive_tool_keyword = /Resources\/Design\/NinjaStyle\.ps1/ nocase ascii wide
                        $string82_AutoRDPwn_offensive_tool_keyword = "Search-cpassword" nocase ascii wide
                        $string83_AutoRDPwn_offensive_tool_keyword = /SessionGopher\.ps1/ nocase ascii wide
                        $string84_AutoRDPwn_offensive_tool_keyword = /Set\-Content\s\-Path\spsexec\.exe/ nocase ascii wide
                        $string85_AutoRDPwn_offensive_tool_keyword = /Set\-Content\s\-Path\sserver\.exe/ nocase ascii wide
                        $string86_AutoRDPwn_offensive_tool_keyword = /Set\-Content\s\-Path\sSharpRDP\.exe/ nocase ascii wide
                        $string87_AutoRDPwn_offensive_tool_keyword = /Set\-Content\s\-Path\sSharpWeb\.exe/ nocase ascii wide
                        $string88_AutoRDPwn_offensive_tool_keyword = /Sherlock\.ps1/ nocase ascii wide
                        $string89_AutoRDPwn_offensive_tool_keyword = /Start\-WebServer\.ps1/ nocase ascii wide
                        $string90_AutoRDPwn_offensive_tool_keyword = "Test-DllExists" nocase ascii wide
                        $string91_AutoRDPwn_offensive_tool_keyword = "Test-ServiceDaclPermission" nocase ascii wide
                        $string92_AutoRDPwn_offensive_tool_keyword = /VNCViewer\.exe\s\/password\sAutoRDPwn\s/ nocase ascii wide
                        $string93_AutoRDPwn_offensive_tool_keyword = "Write-PortscanOut" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}