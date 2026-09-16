rule rule_RuralBishop_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RuralBishop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RuralBishop"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RuralBishop_offensive_tool_keyword = /\/RuralBishop\.git/ nocase ascii wide
                        $string2_RuralBishop_offensive_tool_keyword = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" nocase ascii wide
                        $string3_RuralBishop_offensive_tool_keyword = "rasta-mouse/RuralBishop" nocase ascii wide
                        $string4_RuralBishop_offensive_tool_keyword = /RuralBishop\.csproj/ nocase ascii wide
                        $string5_RuralBishop_offensive_tool_keyword = /RuralBishop\.exe/ nocase ascii wide
                        $string6_RuralBishop_offensive_tool_keyword = /RuralBishop\.sln/ nocase ascii wide
                        $string7_RuralBishop_offensive_tool_keyword = "RuralBishop-master" nocase ascii wide

    condition:
        any of them
}