rule EDRSilencer
{
    meta:
        description = "Detection patterns for the tool 'EDRSilencer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRSilencer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sEDRSilencer\.c/ nocase ascii wide
                        $string2 = /\.exe\sblockedr/ nocase ascii wide
                        $string3 = /\/EDRSilencer\.c/ nocase ascii wide
                        $string4 = /\/EDRSilencer\.git/ nocase ascii wide
                        $string5 = /\\EDRSilencer\.c/ nocase ascii wide
                        $string6 = "Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process" nocase ascii wide
                        $string7 = "Add WFP filters to block the IPv4 and IPv6 outbound traffic of all detected EDR processes" nocase ascii wide
                        $string8 = /EDRSilencer\.exe/ nocase ascii wide
                        $string9 = "netero1010/EDRSilencer" nocase ascii wide

    condition:
        any of them
}