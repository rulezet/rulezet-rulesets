rule rule_SharpMove_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpMove' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMove"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpMove_offensive_tool_keyword = /\.exe\saction\=dcom\scomputername\=.{0,1000}\scommand\=.{0,1000}\sthrow\=wmi\s/ nocase ascii wide
                        $string2_SharpMove_offensive_tool_keyword = /\/SharpMove\.exe/ nocase ascii wide
                        $string3_SharpMove_offensive_tool_keyword = /\/SharpMove\.exe/ nocase ascii wide
                        $string4_SharpMove_offensive_tool_keyword = /\/SharpMove\.git/ nocase ascii wide
                        $string5_SharpMove_offensive_tool_keyword = /\\SharpMove\.exe/ nocase ascii wide
                        $string6_SharpMove_offensive_tool_keyword = /\\SharpMove\.exe/ nocase ascii wide
                        $string7_SharpMove_offensive_tool_keyword = /\\SharpMove\.sln/ nocase ascii wide
                        $string8_SharpMove_offensive_tool_keyword = "0xthirteen/SharpMove" nocase ascii wide
                        $string9_SharpMove_offensive_tool_keyword = "4592e0848e4929ac2b6ba4593f8cbfe09f52ce6ca4206ce52087a31073903645" nocase ascii wide
                        $string10_SharpMove_offensive_tool_keyword = "6093461c4db41a15fefc85a28e35a9e359d0e9452bbfd36ce1fbe7aa31e1f4f0" nocase ascii wide
                        $string11_SharpMove_offensive_tool_keyword = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" nocase ascii wide
                        $string12_SharpMove_offensive_tool_keyword = "'Product'>SharpMove" nocase ascii wide

    condition:
        any of them
}