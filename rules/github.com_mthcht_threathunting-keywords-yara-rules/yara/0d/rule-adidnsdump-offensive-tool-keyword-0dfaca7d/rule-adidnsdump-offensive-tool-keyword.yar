rule rule_adidnsdump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adidnsdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adidnsdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adidnsdump_offensive_tool_keyword = /\sdnsdump\.py/ nocase ascii wide
                        $string2_adidnsdump_offensive_tool_keyword = /\.py\s\-u\s.{0,1000}\s\?print\-zones\s/ nocase ascii wide
                        $string3_adidnsdump_offensive_tool_keyword = /\/adidnsdump\.git/ nocase ascii wide
                        $string4_adidnsdump_offensive_tool_keyword = /\/dnsdump\.py/
                        $string5_adidnsdump_offensive_tool_keyword = /\\dnsdump\.py/ nocase ascii wide
                        $string6_adidnsdump_offensive_tool_keyword = "adidnsdump" nocase ascii wide
                        $string7_adidnsdump_offensive_tool_keyword = "dirkjanm/adidnsdump" nocase ascii wide

    condition:
        any of them
}