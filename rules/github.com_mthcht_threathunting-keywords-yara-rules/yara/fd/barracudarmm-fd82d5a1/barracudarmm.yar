rule BarracudaRMM
{
    meta:
        description = "Detection patterns for the tool 'BarracudaRMM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BarracudaRMM"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.apitest\.barracudamsp\.com/ nocase ascii wide
                        $string2 = "/Applications/Managed Workplace/Onsite Manager/logs/"
                        $string3 = /\\BRMM_2024\.1\-Release/ nocase ascii wide
                        $string4 = /\\MWDiagnosticCollector\.exe/ nocase ascii wide
                        $string5 = /\\MWDiagnosticCollectorResult_.{0,1000}\.zip/ nocase ascii wide
                        $string6 = /\\Program\sFiles\s\(x86\)\\Barracuda\sRMM\\/ nocase ascii wide
                        $string7 = /\\Program\sFiles\s\(x86\)\\Level\sPlatforms\\/ nocase ascii wide
                        $string8 = /\\Program\sFiles\\Barracuda\sRMM\\/ nocase ascii wide
                        $string9 = /\\Program\sFiles\\Level\sPlatforms\\/ nocase ascii wide
                        $string10 = /\\ProgramData\\Barracuda\sMSP\\/ nocase ascii wide
                        $string11 = /\\SOFTWARE\\Level\sPlatforms\\Managed\sWorkplace\\/ nocase ascii wide
                        $string12 = ">Barracuda MSP<" nocase ascii wide
                        $string13 = /\>Barracuda\sNetworks\,\sInc\./ nocase ascii wide
                        $string14 = ">Barracuda RMM Setup AutoRun<" nocase ascii wide
                        $string15 = ">Barracuda RMM Setup<" nocase ascii wide
                        $string16 = /\>Barracuda\sRMM.{0,1000}\</ nocase ascii wide
                        $string17 = ">LPI Level Platforms<" nocase ascii wide
                        $string18 = "Barracuda RMM Onsite Manager - InstallShield Wizard" nocase ascii wide
                        $string19 = /Barracuda\sRMM\sOnsite\sManager\.msi/ nocase ascii wide
                        $string20 = /rmm\.barracudamsp\.com/ nocase ascii wide
                        $string21 = /whatsmyip\.ccrmm\.avg\.com/ nocase ascii wide

    condition:
        any of them
}