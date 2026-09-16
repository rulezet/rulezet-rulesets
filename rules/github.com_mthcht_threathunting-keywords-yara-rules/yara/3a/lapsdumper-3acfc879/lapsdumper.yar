rule LAPSDumper
{
    meta:
        description = "Detection patterns for the tool 'LAPSDumper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSDumper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\slaps\.py\s.{0,1000}\-\-ldapserver/ nocase ascii wide
                        $string2 = /\slaps\.py\s.{0,1000}\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string3 = /\/laps\.py\s.{0,1000}\-\-ldapserver/ nocase ascii wide
                        $string4 = /\/laps\.py\s.{0,1000}\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string5 = /\/LAPSDumper\.git/ nocase ascii wide
                        $string6 = /\\LAPSDumper\\/ nocase ascii wide
                        $string7 = "LAPSDumper-main" nocase ascii wide
                        $string8 = "n00py/LAPSDumper" nocase ascii wide

    condition:
        any of them
}