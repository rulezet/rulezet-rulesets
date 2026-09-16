rule rule_Mshikaki_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Mshikaki' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Mshikaki"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Mshikaki_offensive_tool_keyword = /\sMshikaki\.cpp/ nocase ascii wide
                        $string2_Mshikaki_offensive_tool_keyword = /\/Mshikaki\.git/ nocase ascii wide
                        $string3_Mshikaki_offensive_tool_keyword = /\\Mshikaki\.cpp/ nocase ascii wide
                        $string4_Mshikaki_offensive_tool_keyword = /Mshikaki\.exe/ nocase ascii wide
                        $string5_Mshikaki_offensive_tool_keyword = "Mshikaki-main" nocase ascii wide
                        $string6_Mshikaki_offensive_tool_keyword = "trevorsaudi/Mshikaki" nocase ascii wide

    condition:
        any of them
}