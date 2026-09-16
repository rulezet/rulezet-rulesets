rule PowerSploit
{
    meta:
        description = "Detection patterns for the tool 'PowerSploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerSploit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "Get-NetForestCatalog" nocase ascii wide
                        $string2 = "Get-NetForestDomain" nocase ascii wide
                        $string3 = "Get-NetForestTrust" nocase ascii wide
                        $string4 = "Get-NetSession" nocase ascii wide
                        $string5 = "Get-NetShare" nocase ascii wide
                        $string6 = "Get-NetSubnet" nocase ascii wide
                        $string7 = "Get-RegistryAutoLogon" nocase ascii wide
                        $string8 = "Get-SiteListPassword" nocase ascii wide
                        $string9 = "Get-TimedScreenshot" nocase ascii wide
                        $string10 = "Get-UnquotedService" nocase ascii wide

    condition:
        any of them
}