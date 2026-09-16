rule SharpMove
{
    meta:
        description = "Detection patterns for the tool 'SharpMove' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMove"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\saction\=dcom\scomputername\=.{0,1000}\scommand\=.{0,1000}\sthrow\=wmi\s/ nocase ascii wide
                        $string2 = /\/SharpMove\.exe/ nocase ascii wide
                        $string3 = /\/SharpMove\.exe/ nocase ascii wide
                        $string4 = /\/SharpMove\.git/ nocase ascii wide
                        $string5 = /\\SharpMove\.exe/ nocase ascii wide
                        $string6 = /\\SharpMove\.exe/ nocase ascii wide
                        $string7 = /\\SharpMove\.sln/ nocase ascii wide
                        $string8 = "0xthirteen/SharpMove" nocase ascii wide
                        $string9 = "4592e0848e4929ac2b6ba4593f8cbfe09f52ce6ca4206ce52087a31073903645" nocase ascii wide
                        $string10 = "6093461c4db41a15fefc85a28e35a9e359d0e9452bbfd36ce1fbe7aa31e1f4f0" nocase ascii wide
                        $string11 = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" nocase ascii wide
                        $string12 = "'Product'>SharpMove" nocase ascii wide

    condition:
        any of them
}