rule ThisIsNotRat
{
    meta:
        description = "Detection patterns for the tool 'ThisIsNotRat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThisIsNotRat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/ThisIsNotRat\.git/ nocase ascii wide
                        $string2 = /\/tinar\.py/
                        $string3 = /python\stinar\.py/ nocase ascii wide
                        $string4 = "RealBey/ThisIsNotRat" nocase ascii wide
                        $string5 = "ThisIsNotRat-main" nocase ascii wide

    condition:
        any of them
}