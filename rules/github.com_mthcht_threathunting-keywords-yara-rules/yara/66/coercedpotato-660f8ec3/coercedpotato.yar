rule CoercedPotato
{
    meta:
        description = "Detection patterns for the tool 'CoercedPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CoercedPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/CoercedPotato\.git/ nocase ascii wide
                        $string2 = /\[\+\]\sRUNNING\sALL\sKNOWN\sEXPLOITS/ nocase ascii wide
                        $string3 = /\\\\\\\\\.\\\\pipe\\\\coerced\\\\pipe\\\\spoolss/ nocase ascii wide
                        $string4 = /\\\\\\\\\.\\\\pipe\\\\coerced\\\\pipe\\\\srvsvc/ nocase ascii wide
                        $string5 = /127\.0\.0\.1\/pipe\/coerced\\\\C\$/ nocase ascii wide
                        $string6 = "337ED7BE-969A-40C4-A356-BE99561F4633" nocase ascii wide
                        $string7 = /CoercedPotato\.cpp/ nocase ascii wide
                        $string8 = /CoercedPotato\.exe/ nocase ascii wide
                        $string9 = /CoercedPotato\.sln/ nocase ascii wide
                        $string10 = "CoercedPotato-master" nocase ascii wide
                        $string11 = "Prepouce/CoercedPotato" nocase ascii wide

    condition:
        any of them
}