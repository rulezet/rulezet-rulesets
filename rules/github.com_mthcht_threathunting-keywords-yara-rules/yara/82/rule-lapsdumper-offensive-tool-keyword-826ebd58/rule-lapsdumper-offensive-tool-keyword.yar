rule rule_LAPSDumper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LAPSDumper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSDumper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LAPSDumper_offensive_tool_keyword = /\slaps\.py\s.{0,1000}\-\-ldapserver/ nocase ascii wide
                        $string2_LAPSDumper_offensive_tool_keyword = /\slaps\.py\s.{0,1000}\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string3_LAPSDumper_offensive_tool_keyword = /\/laps\.py\s.{0,1000}\-\-ldapserver/ nocase ascii wide
                        $string4_LAPSDumper_offensive_tool_keyword = /\/laps\.py\s.{0,1000}\-u\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string5_LAPSDumper_offensive_tool_keyword = /\/LAPSDumper\.git/ nocase ascii wide
                        $string6_LAPSDumper_offensive_tool_keyword = /\\LAPSDumper\\/ nocase ascii wide
                        $string7_LAPSDumper_offensive_tool_keyword = "LAPSDumper-main" nocase ascii wide
                        $string8_LAPSDumper_offensive_tool_keyword = "n00py/LAPSDumper" nocase ascii wide

    condition:
        any of them
}