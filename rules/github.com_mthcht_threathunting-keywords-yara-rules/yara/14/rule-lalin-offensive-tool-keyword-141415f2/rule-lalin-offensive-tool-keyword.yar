rule rule_LALIN_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LALIN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LALIN"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LALIN_offensive_tool_keyword = /\sLalin\.sh/ nocase ascii wide
                        $string2_LALIN_offensive_tool_keyword = /\.\/Lalin\.sh/
                        $string3_LALIN_offensive_tool_keyword = /Lalin\.sh\s/
                        $string4_LALIN_offensive_tool_keyword = /lazynmap\.sh/ nocase ascii wide

    condition:
        any of them
}