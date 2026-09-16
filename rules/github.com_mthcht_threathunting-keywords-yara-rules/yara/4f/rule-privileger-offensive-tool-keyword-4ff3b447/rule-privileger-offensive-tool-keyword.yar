rule rule_Privileger_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Privileger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Privileger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Privileger_offensive_tool_keyword = /\/Privileger\.git/ nocase ascii wide
                        $string2_Privileger_offensive_tool_keyword = "MzHmO/Privileger" nocase ascii wide
                        $string3_Privileger_offensive_tool_keyword = /Privileger\.cpp/ nocase ascii wide
                        $string4_Privileger_offensive_tool_keyword = /Privileger\.exe/ nocase ascii wide
                        $string5_Privileger_offensive_tool_keyword = /Privileger\-main\./ nocase ascii wide
                        $string6_Privileger_offensive_tool_keyword = /Privilegerx64\.exe/ nocase ascii wide
                        $string7_Privileger_offensive_tool_keyword = /Privilegerx86\.exe/ nocase ascii wide

    condition:
        any of them
}