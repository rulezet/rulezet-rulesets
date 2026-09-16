rule rule_BarracudaRMM_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BarracudaRMM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BarracudaRMM"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_BarracudaRMM_greyware_tool_keyword = /\.apitest\.barracudamsp\.com/ nocase ascii wide
                        $string2_BarracudaRMM_greyware_tool_keyword = "/Applications/Managed Workplace/Onsite Manager/logs/"
                        $string3_BarracudaRMM_greyware_tool_keyword = /\\BRMM_2024\.1\-Release/ nocase ascii wide
                        $string4_BarracudaRMM_greyware_tool_keyword = /\\MWDiagnosticCollector\.exe/ nocase ascii wide
                        $string5_BarracudaRMM_greyware_tool_keyword = /\\MWDiagnosticCollectorResult_.{0,1000}\.zip/ nocase ascii wide
                        $string6_BarracudaRMM_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Barracuda\sRMM\\/ nocase ascii wide
                        $string7_BarracudaRMM_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Level\sPlatforms\\/ nocase ascii wide
                        $string8_BarracudaRMM_greyware_tool_keyword = /\\Program\sFiles\\Barracuda\sRMM\\/ nocase ascii wide
                        $string9_BarracudaRMM_greyware_tool_keyword = /\\Program\sFiles\\Level\sPlatforms\\/ nocase ascii wide
                        $string10_BarracudaRMM_greyware_tool_keyword = /\\ProgramData\\Barracuda\sMSP\\/ nocase ascii wide
                        $string11_BarracudaRMM_greyware_tool_keyword = /\\SOFTWARE\\Level\sPlatforms\\Managed\sWorkplace\\/ nocase ascii wide
                        $string12_BarracudaRMM_greyware_tool_keyword = ">Barracuda MSP<" nocase ascii wide
                        $string13_BarracudaRMM_greyware_tool_keyword = /\>Barracuda\sNetworks\,\sInc\./ nocase ascii wide
                        $string14_BarracudaRMM_greyware_tool_keyword = ">Barracuda RMM Setup AutoRun<" nocase ascii wide
                        $string15_BarracudaRMM_greyware_tool_keyword = ">Barracuda RMM Setup<" nocase ascii wide
                        $string16_BarracudaRMM_greyware_tool_keyword = /\>Barracuda\sRMM.{0,1000}\</ nocase ascii wide
                        $string17_BarracudaRMM_greyware_tool_keyword = ">LPI Level Platforms<" nocase ascii wide
                        $string18_BarracudaRMM_greyware_tool_keyword = "Barracuda RMM Onsite Manager - InstallShield Wizard" nocase ascii wide
                        $string19_BarracudaRMM_greyware_tool_keyword = /Barracuda\sRMM\sOnsite\sManager\.msi/ nocase ascii wide
                        $string20_BarracudaRMM_greyware_tool_keyword = /rmm\.barracudamsp\.com/ nocase ascii wide
                        $string21_BarracudaRMM_greyware_tool_keyword = /whatsmyip\.ccrmm\.avg\.com/ nocase ascii wide

    condition:
        any of them
}