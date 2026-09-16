rule RuralBishop
{
    meta:
        description = "Detection patterns for the tool 'RuralBishop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RuralBishop"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/RuralBishop\.git/ nocase ascii wide
                        $string2 = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" nocase ascii wide
                        $string3 = "rasta-mouse/RuralBishop" nocase ascii wide
                        $string4 = /RuralBishop\.csproj/ nocase ascii wide
                        $string5 = /RuralBishop\.exe/ nocase ascii wide
                        $string6 = /RuralBishop\.sln/ nocase ascii wide
                        $string7 = "RuralBishop-master" nocase ascii wide

    condition:
        any of them
}