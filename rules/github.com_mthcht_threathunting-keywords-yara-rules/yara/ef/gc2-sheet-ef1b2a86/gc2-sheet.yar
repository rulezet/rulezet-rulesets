rule GC2_sheet
{
    meta:
        description = "Detection patterns for the tool 'GC2-sheet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GC2-sheet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " GC2-sheet" nocase ascii wide
                        $string2 = /\/C2\/c2\.go/ nocase ascii wide
                        $string3 = "/GC2-sheet/" nocase ascii wide
                        $string4 = /\/internal\/C2\/.{0,1000}\.go/ nocase ascii wide
                        $string5 = /gc2\-sheet\.go/ nocase ascii wide
                        $string6 = "GC2-sheet/cmd" nocase ascii wide
                        $string7 = "looCiprian/GC2-sheet" nocase ascii wide

    condition:
        any of them
}