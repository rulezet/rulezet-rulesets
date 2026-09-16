rule icmpsh
{
    meta:
        description = "Detection patterns for the tool 'icmpsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icmpsh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "bdamele/icmpsh" nocase ascii wide
                        $string2 = /icmpsh\.exe/ nocase ascii wide
                        $string3 = /icmpsh\.git/ nocase ascii wide
                        $string4 = /icmpsh_m\.py/ nocase ascii wide
                        $string5 = /icmpsh\-m\./ nocase ascii wide
                        $string6 = "icmpsh-master" nocase ascii wide
                        $string7 = /icmpsh\-s\./ nocase ascii wide

    condition:
        any of them
}