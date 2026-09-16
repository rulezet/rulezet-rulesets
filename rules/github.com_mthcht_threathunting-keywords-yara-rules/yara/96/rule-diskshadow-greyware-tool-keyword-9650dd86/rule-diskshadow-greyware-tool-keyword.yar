rule rule_diskshadow_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'diskshadow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "diskshadow"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_diskshadow_greyware_tool_keyword = "diskshadow /s " nocase ascii wide
                        $string2_diskshadow_greyware_tool_keyword = "diskshadow list shadows all" nocase ascii wide
                        $string3_diskshadow_greyware_tool_keyword = "diskshadow -s " nocase ascii wide
                        $string4_diskshadow_greyware_tool_keyword = /diskshadow\.exe\s\/s\s/ nocase ascii wide
                        $string5_diskshadow_greyware_tool_keyword = /diskshadow\.exe\slist\sshadows\sall/ nocase ascii wide
                        $string6_diskshadow_greyware_tool_keyword = /diskshadow\.exe\s\-s\s/ nocase ascii wide
                        $string7_diskshadow_greyware_tool_keyword = /diskshadow\.exe\\"\s\/s\s/ nocase ascii wide
                        $string8_diskshadow_greyware_tool_keyword = /diskshadow\.exe\\"\slist\sshadows\sall/ nocase ascii wide
                        $string9_diskshadow_greyware_tool_keyword = /diskshadow\.exe\\"\s\-s\s/ nocase ascii wide

    condition:
        any of them
}