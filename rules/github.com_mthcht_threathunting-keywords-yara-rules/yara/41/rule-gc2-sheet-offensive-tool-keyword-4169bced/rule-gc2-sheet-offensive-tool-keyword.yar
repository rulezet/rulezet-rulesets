rule rule_GC2_sheet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GC2-sheet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GC2-sheet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GC2_sheet_offensive_tool_keyword = " GC2-sheet" nocase ascii wide
                        $string2_GC2_sheet_offensive_tool_keyword = /\/C2\/c2\.go/ nocase ascii wide
                        $string3_GC2_sheet_offensive_tool_keyword = "/GC2-sheet/" nocase ascii wide
                        $string4_GC2_sheet_offensive_tool_keyword = /\/internal\/C2\/.{0,1000}\.go/ nocase ascii wide
                        $string5_GC2_sheet_offensive_tool_keyword = /gc2\-sheet\.go/ nocase ascii wide
                        $string6_GC2_sheet_offensive_tool_keyword = "GC2-sheet/cmd" nocase ascii wide
                        $string7_GC2_sheet_offensive_tool_keyword = "looCiprian/GC2-sheet" nocase ascii wide

    condition:
        any of them
}