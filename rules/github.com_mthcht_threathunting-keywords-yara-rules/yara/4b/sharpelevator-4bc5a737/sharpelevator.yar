rule SharpElevator
{
    meta:
        description = "Detection patterns for the tool 'SharpElevator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpElevator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sSharpElevator\.exe/ nocase ascii wide
                        $string2 = /\/SharpElevator\.exe/ nocase ascii wide
                        $string3 = /\/SharpElevator\.git/ nocase ascii wide
                        $string4 = /\[\+\]\sWOOT\!\sCreated\selevated\sprocess\s/ nocase ascii wide
                        $string5 = /\\SharpElevator\.cs/ nocase ascii wide
                        $string6 = /\\SharpElevator\.exe/ nocase ascii wide
                        $string7 = /\\SharpElevator\.sln/ nocase ascii wide
                        $string8 = "378f6e87219651f96e607e40c229e5f17df4ad71836409881fe3cc77c6780ac7" nocase ascii wide
                        $string9 = "42BDEFC0-0BAE-43DF-97BB-C805ABFBD078" nocase ascii wide
                        $string10 = "6a31601415f4b02531aa031b1f246cec9f652f62927bc9b3c4443aac9c2ff625" nocase ascii wide
                        $string11 = "a36ffb4f22598b5e983ef16251df49deb94ad0c41a8a1768503efe4d7e16ea40" nocase ascii wide
                        $string12 = "a67edb34ce2c10bb5c170445344da4ad809932ff8e82e2b6c45a260d5a47a859" nocase ascii wide
                        $string13 = "eladshamir/SharpElevator" nocase ascii wide

    condition:
        any of them
}