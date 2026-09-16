rule rule_SnaffPoint_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SnaffPoint' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SnaffPoint"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SnaffPoint_offensive_tool_keyword = /\/SnaffPoint\.git/ nocase ascii wide
                        $string2_SnaffPoint_offensive_tool_keyword = "879A49C7-0493-4235-85F6-EBF962613A76" nocase ascii wide
                        $string3_SnaffPoint_offensive_tool_keyword = /GetBearerToken\.exe\shttps\:\/\/.{0,1000}\.sharepoint\.com/ nocase ascii wide
                        $string4_SnaffPoint_offensive_tool_keyword = "nheiniger/SnaffPoint" nocase ascii wide
                        $string5_SnaffPoint_offensive_tool_keyword = /SnaffPoint\.exe/ nocase ascii wide
                        $string6_SnaffPoint_offensive_tool_keyword = "SnaffPoint-main" nocase ascii wide

    condition:
        any of them
}