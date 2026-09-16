rule BadPotato
{
    meta:
        description = "Detection patterns for the tool 'BadPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/BadPotato\.exe/ nocase ascii wide
                        $string2 = /\/BadPotato\.git/ nocase ascii wide
                        $string3 = /\\BadPotato\.csproj/ nocase ascii wide
                        $string4 = /\\BadPotato\.exe/ nocase ascii wide
                        $string5 = /\<BadPotato\.exe\>/ nocase ascii wide
                        $string6 = ">BadPotato<" nocase ascii wide
                        $string7 = "0527a14f-1591-4d94-943e-d6d784a50549" nocase ascii wide
                        $string8 = "063bc732edb5ca68d2122d0311ddb46dd38ff05074945566d1fa067c3579d767" nocase ascii wide
                        $string9 = /BadPotato\-master\.zip/ nocase ascii wide
                        $string10 = "BeichenDream/BadPotato" nocase ascii wide

    condition:
        any of them
}