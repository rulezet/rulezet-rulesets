rule rule_TGSThief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TGSThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TGSThief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TGSThief_offensive_tool_keyword = /\/releases\/download\/.{0,1000}\/abc\.exe/ nocase ascii wide
                        $string2_TGSThief_offensive_tool_keyword = /\/TGSThief\.git/ nocase ascii wide
                        $string3_TGSThief_offensive_tool_keyword = "/TGSThief/" nocase ascii wide
                        $string4_TGSThief_offensive_tool_keyword = /\\TGSThief\\/ nocase ascii wide
                        $string5_TGSThief_offensive_tool_keyword = "MzHmO/TGSThief" nocase ascii wide
                        $string6_TGSThief_offensive_tool_keyword = "TGSThief-main" nocase ascii wide

    condition:
        any of them
}