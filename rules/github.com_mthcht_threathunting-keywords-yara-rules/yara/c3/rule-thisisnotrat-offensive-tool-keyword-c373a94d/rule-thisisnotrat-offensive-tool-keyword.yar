rule rule_ThisIsNotRat_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ThisIsNotRat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThisIsNotRat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ThisIsNotRat_offensive_tool_keyword = /\/ThisIsNotRat\.git/ nocase ascii wide
                        $string2_ThisIsNotRat_offensive_tool_keyword = /\/tinar\.py/
                        $string3_ThisIsNotRat_offensive_tool_keyword = /python\stinar\.py/ nocase ascii wide
                        $string4_ThisIsNotRat_offensive_tool_keyword = "RealBey/ThisIsNotRat" nocase ascii wide
                        $string5_ThisIsNotRat_offensive_tool_keyword = "ThisIsNotRat-main" nocase ascii wide

    condition:
        any of them
}