rule rule_PowerSploit_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerSploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerSploit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_PowerSploit_greyware_tool_keyword = "Get-NetForestCatalog" nocase ascii wide
                        $string2_PowerSploit_greyware_tool_keyword = "Get-NetForestDomain" nocase ascii wide
                        $string3_PowerSploit_greyware_tool_keyword = "Get-NetForestTrust" nocase ascii wide
                        $string4_PowerSploit_greyware_tool_keyword = "Get-NetSession" nocase ascii wide
                        $string5_PowerSploit_greyware_tool_keyword = "Get-NetShare" nocase ascii wide
                        $string6_PowerSploit_greyware_tool_keyword = "Get-NetSubnet" nocase ascii wide
                        $string7_PowerSploit_greyware_tool_keyword = "Get-RegistryAutoLogon" nocase ascii wide
                        $string8_PowerSploit_greyware_tool_keyword = "Get-SiteListPassword" nocase ascii wide
                        $string9_PowerSploit_greyware_tool_keyword = "Get-TimedScreenshot" nocase ascii wide
                        $string10_PowerSploit_greyware_tool_keyword = "Get-UnquotedService" nocase ascii wide

    condition:
        any of them
}