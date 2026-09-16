rule rule_polenum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'polenum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "polenum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_polenum_offensive_tool_keyword = /\spolenum\.py/ nocase ascii wide
                        $string2_polenum_offensive_tool_keyword = /\/polenum\.py/
                        $string3_polenum_offensive_tool_keyword = "/usr/bin/polenum"
                        $string4_polenum_offensive_tool_keyword = /\\polenum\.py/ nocase ascii wide
                        $string5_polenum_offensive_tool_keyword = "apt install polenum" nocase ascii wide
                        $string6_polenum_offensive_tool_keyword = /polenum\s.{0,1000}\-protocols\s/ nocase ascii wide
                        $string7_polenum_offensive_tool_keyword = "polenum -h" nocase ascii wide

    condition:
        any of them
}