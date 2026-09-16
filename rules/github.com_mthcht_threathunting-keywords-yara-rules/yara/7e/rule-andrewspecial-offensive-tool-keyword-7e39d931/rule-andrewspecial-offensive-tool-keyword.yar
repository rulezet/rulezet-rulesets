rule rule_AndrewSpecial_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AndrewSpecial' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AndrewSpecial"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AndrewSpecial_offensive_tool_keyword = /\/AndrewSpecial\.git/ nocase ascii wide
                        $string2_AndrewSpecial_offensive_tool_keyword = /\\Andrew\.dmp/ nocase ascii wide
                        $string3_AndrewSpecial_offensive_tool_keyword = /AndrewSpecial\.cpp/ nocase ascii wide
                        $string4_AndrewSpecial_offensive_tool_keyword = /AndrewSpecial\.exe/ nocase ascii wide
                        $string5_AndrewSpecial_offensive_tool_keyword = "AndrewSpecial-master" nocase ascii wide
                        $string6_AndrewSpecial_offensive_tool_keyword = "hoangprod/AndrewSpecial" nocase ascii wide

    condition:
        any of them
}