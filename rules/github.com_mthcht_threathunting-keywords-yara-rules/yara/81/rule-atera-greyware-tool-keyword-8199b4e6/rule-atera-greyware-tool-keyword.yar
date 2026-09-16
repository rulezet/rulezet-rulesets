rule rule_Atera_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Atera' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Atera"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Atera_greyware_tool_keyword = /\.servicedesk\.atera\.com\/GetAgent/ nocase ascii wide
                        $string2_Atera_greyware_tool_keyword = "/Agent/AcknowledgeCommands/" nocase ascii wide
                        $string3_Atera_greyware_tool_keyword = "/Agent/GetCommandsFallback/" nocase ascii wide
                        $string4_Atera_greyware_tool_keyword = "/Agent/GetEnvironmentStatus/" nocase ascii wide
                        $string5_Atera_greyware_tool_keyword = "/Agent/GetRecurringPackages/" nocase ascii wide
                        $string6_Atera_greyware_tool_keyword = /\\AlphaControlAgent\\obj\\Release\\AteraAgent\.pdb/ nocase ascii wide
                        $string7_Atera_greyware_tool_keyword = /\\atera_agent\.exe/ nocase ascii wide
                        $string8_Atera_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Atera\sNetworks/ nocase ascii wide
                        $string9_Atera_greyware_tool_keyword = /\\Program\sFiles\\Atera\sNetworks/ nocase ascii wide
                        $string10_Atera_greyware_tool_keyword = /\\Services\\AteraAgent/ nocase ascii wide
                        $string11_Atera_greyware_tool_keyword = /\\TEMP\\AteraUpgradeAgentPackage\\/ nocase ascii wide
                        $string12_Atera_greyware_tool_keyword = ">Atera Networks<" nocase ascii wide
                        $string13_Atera_greyware_tool_keyword = /acontrol\.atera\.com/ nocase ascii wide
                        $string14_Atera_greyware_tool_keyword = /agent\-api\.atera\.com/ nocase ascii wide
                        $string15_Atera_greyware_tool_keyword = /AgentPackageInternalPooler\\log\.txt/ nocase ascii wide
                        $string16_Atera_greyware_tool_keyword = /AgentPackageRunCommandInteractive\\log\.txt/ nocase ascii wide
                        $string17_Atera_greyware_tool_keyword = /AlphaControlAgent\.CloudLogsManager\+\<\>/ nocase ascii wide
                        $string18_Atera_greyware_tool_keyword = /atera_del\.bat/ nocase ascii wide
                        $string19_Atera_greyware_tool_keyword = /atera_del2\.bat/ nocase ascii wide
                        $string20_Atera_greyware_tool_keyword = /AteraAgent.{0,1000}AgentPackageRunCommandInteractive\.exe/ nocase ascii wide
                        $string21_Atera_greyware_tool_keyword = /AteraSetupLog\.txt/ nocase ascii wide
                        $string22_Atera_greyware_tool_keyword = /HKEY_CURRENT_USER\\Software\\ATERA\sNetworks/ nocase ascii wide
                        $string23_Atera_greyware_tool_keyword = /HKEY_LOCAL_MACHINE\\SOFTWARE\\ATERA\sNetworks/ nocase ascii wide
                        $string24_Atera_greyware_tool_keyword = /http.{0,1000}\/agent\-api\-.{0,1000}\.atera\.com/ nocase ascii wide
                        $string25_Atera_greyware_tool_keyword = "Monitoring & Management Agent by ATERA" nocase ascii wide
                        $string26_Atera_greyware_tool_keyword = /REG\sDELETE\s\\"HKEY_CLASSES_ROOT\\Installer\\Products\\10F15BFE50893924BB61F671FEC4D2EF\\"\s\/f/ nocase ascii wide
                        $string27_Atera_greyware_tool_keyword = /REG\sDELETE\s\\"HKEY_CLASSES_ROOT\\Installer\\Products\\4758948C95C1B194AB15204D95B42292\\"\s\/f/ nocase ascii wide
                        $string28_Atera_greyware_tool_keyword = "sc delete AteraAgent" nocase ascii wide
                        $string29_Atera_greyware_tool_keyword = "sc start AteraAgent" nocase ascii wide
                        $string30_Atera_greyware_tool_keyword = "sc stop AteraAgent" nocase ascii wide
                        $string31_Atera_greyware_tool_keyword = /SOFTWARE\\ATERA\sNetworks\\AlphaAgent/ nocase ascii wide
                        $string32_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sAgentPackageAgentInformation\.exe/ nocase ascii wide
                        $string33_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sAgentPackageEventViewer\.exe/ nocase ascii wide
                        $string34_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sAgentPackageHeartbeat\.exe/ nocase ascii wide
                        $string35_Atera_greyware_tool_keyword = "taskkill /f /im AgentPackageInformation" nocase ascii wide
                        $string36_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sAgentPackageInternalPoller\.exe/ nocase ascii wide
                        $string37_Atera_greyware_tool_keyword = "taskkill /f /im AgentPackageMonitoring" nocase ascii wide
                        $string38_Atera_greyware_tool_keyword = "taskkill /f /im AgentPackageProgramManagement" nocase ascii wide
                        $string39_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sAgentPackageRegistryExplorer\.exe/ nocase ascii wide
                        $string40_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sAgentPackageRunCommande\.exe/ nocase ascii wide
                        $string41_Atera_greyware_tool_keyword = "taskkill /f /im AgentPackageRunCommandInteractive" nocase ascii wide
                        $string42_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sAgentPackageSTRemote\.exe/ nocase ascii wide
                        $string43_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sAgentPackageSystemTools\.exe/ nocase ascii wide
                        $string44_Atera_greyware_tool_keyword = "taskkill /f /im AgentPackageUpgradeAgent" nocase ascii wide
                        $string45_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sAgentPackageWindowsUpdate\.exe/ nocase ascii wide
                        $string46_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sAteraAgent\.exe/ nocase ascii wide
                        $string47_Atera_greyware_tool_keyword = /taskkill\s\/f\s\/im\sTicketingTray\.exe/ nocase ascii wide

    condition:
        any of them
}