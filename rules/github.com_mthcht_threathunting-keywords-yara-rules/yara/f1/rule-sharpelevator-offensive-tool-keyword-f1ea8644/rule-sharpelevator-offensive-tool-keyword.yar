rule rule_SharpElevator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpElevator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpElevator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpElevator_offensive_tool_keyword = /\sSharpElevator\.exe/ nocase ascii wide
                        $string2_SharpElevator_offensive_tool_keyword = /\/SharpElevator\.exe/ nocase ascii wide
                        $string3_SharpElevator_offensive_tool_keyword = /\/SharpElevator\.git/ nocase ascii wide
                        $string4_SharpElevator_offensive_tool_keyword = /\[\+\]\sWOOT\!\sCreated\selevated\sprocess\s/ nocase ascii wide
                        $string5_SharpElevator_offensive_tool_keyword = /\\SharpElevator\.cs/ nocase ascii wide
                        $string6_SharpElevator_offensive_tool_keyword = /\\SharpElevator\.exe/ nocase ascii wide
                        $string7_SharpElevator_offensive_tool_keyword = /\\SharpElevator\.sln/ nocase ascii wide
                        $string8_SharpElevator_offensive_tool_keyword = "378f6e87219651f96e607e40c229e5f17df4ad71836409881fe3cc77c6780ac7" nocase ascii wide
                        $string9_SharpElevator_offensive_tool_keyword = "42BDEFC0-0BAE-43DF-97BB-C805ABFBD078" nocase ascii wide
                        $string10_SharpElevator_offensive_tool_keyword = "6a31601415f4b02531aa031b1f246cec9f652f62927bc9b3c4443aac9c2ff625" nocase ascii wide
                        $string11_SharpElevator_offensive_tool_keyword = "a36ffb4f22598b5e983ef16251df49deb94ad0c41a8a1768503efe4d7e16ea40" nocase ascii wide
                        $string12_SharpElevator_offensive_tool_keyword = "a67edb34ce2c10bb5c170445344da4ad809932ff8e82e2b6c45a260d5a47a859" nocase ascii wide
                        $string13_SharpElevator_offensive_tool_keyword = "eladshamir/SharpElevator" nocase ascii wide

    condition:
        any of them
}