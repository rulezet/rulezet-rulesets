rule Atera
{
    meta:
        description = "Detection patterns for the tool 'Atera' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Atera"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.servicedesk\.atera\.com\/GetAgent/ nocase ascii wide
                        $string2 = "/Agent/AcknowledgeCommands/" nocase ascii wide
                        $string3 = "/Agent/GetCommandsFallback/" nocase ascii wide
                        $string4 = "/Agent/GetEnvironmentStatus/" nocase ascii wide
                        $string5 = "/Agent/GetRecurringPackages/" nocase ascii wide
                        $string6 = /\\AlphaControlAgent\\obj\\Release\\AteraAgent\.pdb/ nocase ascii wide
                        $string7 = /\\atera_agent\.exe/ nocase ascii wide
                        $string8 = /\\Program\sFiles\s\(x86\)\\Atera\sNetworks/ nocase ascii wide
                        $string9 = /\\Program\sFiles\\Atera\sNetworks/ nocase ascii wide
                        $string10 = /\\Services\\AteraAgent/ nocase ascii wide
                        $string11 = /\\TEMP\\AteraUpgradeAgentPackage\\/ nocase ascii wide
                        $string12 = ">Atera Networks<" nocase ascii wide
                        $string13 = /acontrol\.atera\.com/ nocase ascii wide
                        $string14 = /agent\-api\.atera\.com/ nocase ascii wide
                        $string15 = /AgentPackageInternalPooler\\log\.txt/ nocase ascii wide
                        $string16 = /AgentPackageRunCommandInteractive\\log\.txt/ nocase ascii wide
                        $string17 = /AlphaControlAgent\.CloudLogsManager\+\<\>/ nocase ascii wide
                        $string18 = /atera_del\.bat/ nocase ascii wide
                        $string19 = /atera_del2\.bat/ nocase ascii wide
                        $string20 = /AteraAgent.{0,100}AgentPackageRunCommandInteractive\.exe/ nocase ascii wide
                        $string21 = /AteraSetupLog\.txt/ nocase ascii wide
                        $string22 = /HKEY_CURRENT_USER\\Software\\ATERA\sNetworks/ nocase ascii wide
                        $string23 = /HKEY_LOCAL_MACHINE\\SOFTWARE\\ATERA\sNetworks/ nocase ascii wide
                        $string24 = /http.{0,100}\/agent\-api\-.{0,100}\.atera\.com/ nocase ascii wide
                        $string25 = "Monitoring & Management Agent by ATERA" nocase ascii wide
                        $string26 = /REG\sDELETE\s\\"HKEY_CLASSES_ROOT\\Installer\\Products\\10F15BFE50893924BB61F671FEC4D2EF\\"\s\/f/ nocase ascii wide
                        $string27 = /REG\sDELETE\s\\"HKEY_CLASSES_ROOT\\Installer\\Products\\4758948C95C1B194AB15204D95B42292\\"\s\/f/ nocase ascii wide
                        $string28 = "sc delete AteraAgent" nocase ascii wide
                        $string29 = "sc start AteraAgent" nocase ascii wide
                        $string30 = "sc stop AteraAgent" nocase ascii wide
                        $string31 = /SOFTWARE\\ATERA\sNetworks\\AlphaAgent/ nocase ascii wide
                        $string32 = /taskkill\s\/f\s\/im\sAgentPackageAgentInformation\.exe/ nocase ascii wide
                        $string33 = /taskkill\s\/f\s\/im\sAgentPackageEventViewer\.exe/ nocase ascii wide
                        $string34 = /taskkill\s\/f\s\/im\sAgentPackageHeartbeat\.exe/ nocase ascii wide
                        $string35 = "taskkill /f /im AgentPackageInformation" nocase ascii wide
                        $string36 = /taskkill\s\/f\s\/im\sAgentPackageInternalPoller\.exe/ nocase ascii wide
                        $string37 = "taskkill /f /im AgentPackageMonitoring" nocase ascii wide
                        $string38 = "taskkill /f /im AgentPackageProgramManagement" nocase ascii wide
                        $string39 = /taskkill\s\/f\s\/im\sAgentPackageRegistryExplorer\.exe/ nocase ascii wide
                        $string40 = /taskkill\s\/f\s\/im\sAgentPackageRunCommande\.exe/ nocase ascii wide
                        $string41 = "taskkill /f /im AgentPackageRunCommandInteractive" nocase ascii wide
                        $string42 = /taskkill\s\/f\s\/im\sAgentPackageSTRemote\.exe/ nocase ascii wide
                        $string43 = /taskkill\s\/f\s\/im\sAgentPackageSystemTools\.exe/ nocase ascii wide
                        $string44 = "taskkill /f /im AgentPackageUpgradeAgent" nocase ascii wide
                        $string45 = /taskkill\s\/f\s\/im\sAgentPackageWindowsUpdate\.exe/ nocase ascii wide
                        $string46 = /taskkill\s\/f\s\/im\sAteraAgent\.exe/ nocase ascii wide
                        $string47 = /taskkill\s\/f\s\/im\sTicketingTray\.exe/ nocase ascii wide
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