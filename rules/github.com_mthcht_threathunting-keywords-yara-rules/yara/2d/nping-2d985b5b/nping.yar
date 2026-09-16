rule nping
{
    meta:
        description = "Detection patterns for the tool 'nping' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nping"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\-c1\s.{0,1000}\s\-\-data\-string\s.{0,1000}\s\-\-icmp\s/ nocase ascii wide
                        $string2 = /\s\-c1\s.{0,1000}\s\-\-icmp\s.{0,1000}\s\-\-data\-string\s/ nocase ascii wide
                        $string3 = /\s\-\-data\-string\s.{0,1000}\s\-c1\s.{0,1000}\s\-\-icmp\s/ nocase ascii wide
                        $string4 = /\s\-\-data\-string\s.{0,1000}\s\-\-icmp\s.{0,1000}\s\-c1\s/ nocase ascii wide
                        $string5 = /\s\-\-icmp\s.{0,1000}\s\-c1\s.{0,1000}\s\-\-data\-string\s/ nocase ascii wide
                        $string6 = /\s\-\-icmp\s.{0,1000}\s\-\-data\-string\s.{0,1000}\s\-c1\s/ nocase ascii wide
                        $string7 = /nping.{0,1000}\s\-\-data\s/ nocase ascii wide
                        $string8 = /nping.{0,1000}\s\-\-data\-string\s/ nocase ascii wide
                        $string9 = /nping.{0,1000}\s\-\-icmp\s/ nocase ascii wide

    condition:
        any of them
}