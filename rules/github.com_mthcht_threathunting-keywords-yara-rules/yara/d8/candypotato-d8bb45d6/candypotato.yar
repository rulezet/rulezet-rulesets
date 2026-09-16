rule CandyPotato
{
    meta:
        description = "Detection patterns for the tool 'CandyPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CandyPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/CandyPotato\.cpp/ nocase ascii wide
                        $string2 = /\/CandyPotato\.sdf/ nocase ascii wide
                        $string3 = /\/CandyPotato\.sln/ nocase ascii wide
                        $string4 = /\/CandyPotato\.vcxproj/ nocase ascii wide
                        $string5 = "/klezVirus/CandyPotato" nocase ascii wide
                        $string6 = /CandyPotato\.exe\s/ nocase ascii wide

    condition:
        any of them
}