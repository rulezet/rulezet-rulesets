rule rule_CandyPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CandyPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CandyPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CandyPotato_offensive_tool_keyword = /\/CandyPotato\.cpp/ nocase ascii wide
                        $string2_CandyPotato_offensive_tool_keyword = /\/CandyPotato\.sdf/ nocase ascii wide
                        $string3_CandyPotato_offensive_tool_keyword = /\/CandyPotato\.sln/ nocase ascii wide
                        $string4_CandyPotato_offensive_tool_keyword = /\/CandyPotato\.vcxproj/ nocase ascii wide
                        $string5_CandyPotato_offensive_tool_keyword = "/klezVirus/CandyPotato" nocase ascii wide
                        $string6_CandyPotato_offensive_tool_keyword = /CandyPotato\.exe\s/ nocase ascii wide

    condition:
        any of them
}