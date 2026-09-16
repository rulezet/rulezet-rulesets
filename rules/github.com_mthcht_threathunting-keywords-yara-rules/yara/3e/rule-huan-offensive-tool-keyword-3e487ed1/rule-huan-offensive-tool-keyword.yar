rule rule_Huan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Huan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Huan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Huan_offensive_tool_keyword = /\/huan\.exe\s/ nocase ascii wide
                        $string2_Huan_offensive_tool_keyword = "/HuanLoader/" nocase ascii wide
                        $string3_Huan_offensive_tool_keyword = /\\huan\.exe\s/ nocase ascii wide
                        $string4_Huan_offensive_tool_keyword = /huan\.exe\s.{0,1000}\.exe/ nocase ascii wide
                        $string5_Huan_offensive_tool_keyword = /Huan\.sln/ nocase ascii wide
                        $string6_Huan_offensive_tool_keyword = /Huan\.vcxproj/ nocase ascii wide
                        $string7_Huan_offensive_tool_keyword = /HuanLoader\.vcxproj/ nocase ascii wide

    condition:
        any of them
}