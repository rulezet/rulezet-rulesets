rule rule_nping_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nping' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nping"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_nping_greyware_tool_keyword = /\s\-c1\s.{0,1000}\s\-\-data\-string\s.{0,1000}\s\-\-icmp\s/ nocase ascii wide
                        $string2_nping_greyware_tool_keyword = /\s\-c1\s.{0,1000}\s\-\-icmp\s.{0,1000}\s\-\-data\-string\s/ nocase ascii wide
                        $string3_nping_greyware_tool_keyword = /\s\-\-data\-string\s.{0,1000}\s\-c1\s.{0,1000}\s\-\-icmp\s/ nocase ascii wide
                        $string4_nping_greyware_tool_keyword = /\s\-\-data\-string\s.{0,1000}\s\-\-icmp\s.{0,1000}\s\-c1\s/ nocase ascii wide
                        $string5_nping_greyware_tool_keyword = /\s\-\-icmp\s.{0,1000}\s\-c1\s.{0,1000}\s\-\-data\-string\s/ nocase ascii wide
                        $string6_nping_greyware_tool_keyword = /\s\-\-icmp\s.{0,1000}\s\-\-data\-string\s.{0,1000}\s\-c1\s/ nocase ascii wide
                        $string7_nping_greyware_tool_keyword = /nping.{0,1000}\s\-\-data\s/ nocase ascii wide
                        $string8_nping_greyware_tool_keyword = /nping.{0,1000}\s\-\-data\-string\s/ nocase ascii wide
                        $string9_nping_greyware_tool_keyword = /nping.{0,1000}\s\-\-icmp\s/ nocase ascii wide

    condition:
        any of them
}