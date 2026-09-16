rule PrivescCheck
{
    meta:
        description = "Detection patterns for the tool 'PrivescCheck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivescCheck"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Get-ServiceFromRegistry -Name Spooler" nocase ascii wide
                        $string2 = " -Report PrivescCheck_" nocase ascii wide
                        $string3 = " -Report PrivescCheck_" nocase ascii wide
                        $string4 = /\$LolDriversVulnerable/ nocase ascii wide
                        $string5 = "/PrivescCheck" nocase ascii wide
                        $string6 = /\\PrivescCheck/ nocase ascii wide
                        $string7 = /\\PrivescCheck_/ nocase ascii wide
                        $string8 = /\\PrivescCheck_/ nocase ascii wide
                        $string9 = /\\src\\check\\Credentials\.ps1/ nocase ascii wide
                        $string10 = "<title>PrivescCheck Report</title>" nocase ascii wide
                        $string11 = "Find-ProtectionSoftware" nocase ascii wide
                        $string12 = "Get-AclModificationRights" nocase ascii wide
                        $string13 = "Get-DecodedPassword" nocase ascii wide
                        $string14 = "Get-DecryptedPassword" nocase ascii wide
                        $string15 = "Get-ExploitableUnquotedPath" nocase ascii wide
                        $string16 = "Get-LolDrivers" nocase ascii wide
                        $string17 = "Get-RemoteDesktopUserSessionList" nocase ascii wide
                        $string18 = /Get\-RemoteDesktopUserSessionList\./ nocase ascii wide
                        $string19 = "Get-SccmCacheFolder" nocase ascii wide
                        $string20 = "Get-ShadowCopies" nocase ascii wide
                        $string21 = "Get-VaultCreds" nocase ascii wide
                        $string22 = "Invoke-AirstrikeAttackCheck" nocase ascii wide
                        $string23 = "Invoke-AirstrikeAttackCheck" nocase ascii wide
                        $string24 = "Invoke-ApplicationsOnStartupCheck" nocase ascii wide
                        $string25 = "Invoke-BitlockerCheck" nocase ascii wide
                        $string26 = "Invoke-CcmNaaCredentialsCheck" nocase ascii wide
                        $string27 = "Invoke-CredentialFilesCheck" nocase ascii wide
                        $string28 = "Invoke-CredentialGuardCheck" nocase ascii wide
                        $string29 = "Invoke-DefenderExclusionsCheck" nocase ascii wide
                        $string30 = "Invoke-DllHijackingCheck" nocase ascii wide
                        $string31 = "Invoke-DriverCoInstallersCheck" nocase ascii wide
                        $string32 = "Invoke-EndpointProtectionCheck" nocase ascii wide
                        $string33 = "Invoke-ExploitableLeakedHandlesCheck" nocase ascii wide
                        $string34 = "Invoke-GPPPasswordCheck" nocase ascii wide
                        $string35 = "Invoke-HardenedUNCPathCheck" nocase ascii wide
                        $string36 = "Invoke-HijackableDllsCheck" nocase ascii wide
                        $string37 = "Invoke-HotFixVulnCheck" nocase ascii wide
                        $string38 = "Invoke-InstalledProgramsCheck" nocase ascii wide
                        $string39 = "Invoke-InstalledServicesCheck" nocase ascii wide
                        $string40 = "Invoke-LapsCheck" nocase ascii wide
                        $string41 = "Invoke-LocalAdminGroupCheck" nocase ascii wide
                        $string42 = "Invoke-LsaProtectionCheck" nocase ascii wide
                        $string43 = "Invoke-MachineRoleCheck" nocase ascii wide
                        $string44 = "Invoke-ModifiableProgramsCheck" nocase ascii wide
                        $string45 = "Invoke-NamedPipePermissionsCheck" nocase ascii wide
                        $string46 = "Invoke-NetworkAdaptersCheck" nocase ascii wide
                        $string47 = "Invoke-PowerShellHistoryCheck" nocase ascii wide
                        $string48 = "Invoke-PowershellTranscriptionCheck" nocase ascii wide
                        $string49 = "Invoke-PrintNightmareCheck" nocase ascii wide
                        $string50 = "Invoke-PrivescCheck" nocase ascii wide
                        $string51 = "Invoke-RegistryAlwaysInstallElevatedCheck" nocase ascii wide
                        $string52 = "Invoke-RegistryAlwaysInstallElevatedCheck" nocase ascii wide
                        $string53 = "Invoke-RunningProcessCheck" nocase ascii wide
                        $string54 = "Invoke-SccmCacheFolderCheck" nocase ascii wide
                        $string55 = "Invoke-ScheduledTasksImagePermissionsCheck" nocase ascii wide
                        $string56 = "Invoke-ScheduledTasksUnquotedPathCheck" nocase ascii wide
                        $string57 = "Invoke-SCMPermissionsCheck" nocase ascii wide
                        $string58 = "Invoke-SensitiveHiveFileAccessCheck" nocase ascii wide
                        $string59 = "Invoke-SensitiveHiveShadowCopyCheck" nocase ascii wide
                        $string60 = "Invoke-ServicesImagePermissionsCheck" nocase ascii wide
                        $string61 = "Invoke-ServicesPermissionsCheck" nocase ascii wide
                        $string62 = "Invoke-ServicesPermissionsRegistryCheck" nocase ascii wide
                        $string63 = "Invoke-ServicesUnquotedPathCheck" nocase ascii wide
                        $string64 = "Invoke-SystemStartupCheck" nocase ascii wide
                        $string65 = "Invoke-SystemStartupHistoryCheck" nocase ascii wide
                        $string66 = "Invoke-TcpEndpointsCheck" nocase ascii wide
                        $string67 = "Invoke-ThirdPartyDriversCheck" nocase ascii wide
                        $string68 = "Invoke-UacCheck" nocase ascii wide
                        $string69 = "Invoke-UdpEndpointsCheck" nocase ascii wide
                        $string70 = "Invoke-UnattendFilesCheck" nocase ascii wide
                        $string71 = "Invoke-UserCheck" nocase ascii wide
                        $string72 = "Invoke-UserEnvCheck" nocase ascii wide
                        $string73 = "Invoke-UserGroupsCheck" nocase ascii wide
                        $string74 = "Invoke-UserPrivilegesCheck" nocase ascii wide
                        $string75 = "Invoke-UserRestrictedSidsCheck" nocase ascii wide
                        $string76 = "Invoke-UserSessionListCheck" nocase ascii wide
                        $string77 = "Invoke-UsersHomeFolderCheck" nocase ascii wide
                        $string78 = "Invoke-VaultCredCheck" nocase ascii wide
                        $string79 = "Invoke-VaultListCheck" nocase ascii wide
                        $string80 = "Invoke-WindowsUpdateCheck" nocase ascii wide
                        $string81 = "Invoke-WinlogonCheck" nocase ascii wide
                        $string82 = "Invoke-WlanProfilesCheck" nocase ascii wide
                        $string83 = "itm4n/PrivescCheck" nocase ascii wide
                        $string84 = /Microsoft\\Windows\\Recent\\PrivescCheck/ nocase ascii wide
                        $string85 = "MISC_HIJACKABLE_DLL" nocase ascii wide
                        $string86 = /Password.{0,100}S0urce0fThePr0blem/ nocase ascii wide
                        $string87 = /Password.{0,100}S3cr3tS3rvic3/ nocase ascii wide
                        $string88 = /PointAndPrint\.ps1/ nocase ascii wide
                        $string89 = /PrivescCheck\.ps1/ nocase ascii wide
                        $string90 = /PrivescCheck_.{0,100}\./ nocase ascii wide
                        $string91 = "PrivescCheckAsciiReport" nocase ascii wide
                        $string92 = "Test-DllExists" nocase ascii wide
                        $string93 = "Test-HijackableDll" nocase ascii wide
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