rule rule_sniffer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sniffer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sniffer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sniffer_offensive_tool_keyword = /\/sniffer\.git/ nocase ascii wide
                        $string2_sniffer_offensive_tool_keyword = "brew install sniffer" nocase ascii wide
                        $string3_sniffer_offensive_tool_keyword = "chenjiandongx/sniffer" nocase ascii wide
                        $string4_sniffer_offensive_tool_keyword = /sniffer\-master\.zip/ nocase ascii wide

    condition:
        any of them
}