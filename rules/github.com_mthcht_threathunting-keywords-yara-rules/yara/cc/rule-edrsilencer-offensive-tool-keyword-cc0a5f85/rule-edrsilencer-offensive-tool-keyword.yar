rule rule_EDRSilencer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EDRSilencer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRSilencer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EDRSilencer_offensive_tool_keyword = /\sEDRSilencer\.c/ nocase ascii wide
                        $string2_EDRSilencer_offensive_tool_keyword = /\.exe\sblockedr/ nocase ascii wide
                        $string3_EDRSilencer_offensive_tool_keyword = /\/EDRSilencer\.c/ nocase ascii wide
                        $string4_EDRSilencer_offensive_tool_keyword = /\/EDRSilencer\.git/ nocase ascii wide
                        $string5_EDRSilencer_offensive_tool_keyword = /\\EDRSilencer\.c/ nocase ascii wide
                        $string6_EDRSilencer_offensive_tool_keyword = "Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process" nocase ascii wide
                        $string7_EDRSilencer_offensive_tool_keyword = "Add WFP filters to block the IPv4 and IPv6 outbound traffic of all detected EDR processes" nocase ascii wide
                        $string8_EDRSilencer_offensive_tool_keyword = /EDRSilencer\.exe/ nocase ascii wide
                        $string9_EDRSilencer_offensive_tool_keyword = "netero1010/EDRSilencer" nocase ascii wide

    condition:
        any of them
}