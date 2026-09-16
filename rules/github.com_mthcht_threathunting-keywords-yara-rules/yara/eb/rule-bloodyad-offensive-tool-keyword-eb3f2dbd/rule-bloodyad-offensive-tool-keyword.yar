rule rule_bloodyAD_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bloodyAD' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bloodyAD"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bloodyAD_offensive_tool_keyword = /\/bloodyAD\.git/ nocase ascii wide
                        $string2_bloodyAD_offensive_tool_keyword = "bloodyAD -" nocase ascii wide
                        $string3_bloodyAD_offensive_tool_keyword = /bloodyAD\.py/ nocase ascii wide
                        $string4_bloodyAD_offensive_tool_keyword = "bloodyAD-main" nocase ascii wide
                        $string5_bloodyAD_offensive_tool_keyword = "CravateRouge/bloodyAD" nocase ascii wide

    condition:
        any of them
}