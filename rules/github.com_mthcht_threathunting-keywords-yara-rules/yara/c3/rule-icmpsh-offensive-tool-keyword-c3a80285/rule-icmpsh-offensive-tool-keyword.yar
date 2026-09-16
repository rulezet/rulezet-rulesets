rule rule_icmpsh_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'icmpsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icmpsh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_icmpsh_offensive_tool_keyword = "bdamele/icmpsh" nocase ascii wide
                        $string2_icmpsh_offensive_tool_keyword = /icmpsh\.exe/ nocase ascii wide
                        $string3_icmpsh_offensive_tool_keyword = /icmpsh\.git/ nocase ascii wide
                        $string4_icmpsh_offensive_tool_keyword = /icmpsh_m\.py/ nocase ascii wide
                        $string5_icmpsh_offensive_tool_keyword = /icmpsh\-m\./ nocase ascii wide
                        $string6_icmpsh_offensive_tool_keyword = "icmpsh-master" nocase ascii wide
                        $string7_icmpsh_offensive_tool_keyword = /icmpsh\-s\./ nocase ascii wide

    condition:
        any of them
}