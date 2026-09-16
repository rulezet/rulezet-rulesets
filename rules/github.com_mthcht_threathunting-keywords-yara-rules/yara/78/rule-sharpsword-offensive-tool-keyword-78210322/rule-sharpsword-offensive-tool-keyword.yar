rule rule_SharpSword_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSword"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSword_offensive_tool_keyword = /\/SharpSword\.git/ nocase ascii wide
                        $string2_SharpSword_offensive_tool_keyword = "9E357027-8AA6-4376-8146-F5AF610E14BB" nocase ascii wide
                        $string3_SharpSword_offensive_tool_keyword = "OG-Sadpanda/SharpSword" nocase ascii wide
                        $string4_SharpSword_offensive_tool_keyword = /SharpSword\.csproj/ nocase ascii wide
                        $string5_SharpSword_offensive_tool_keyword = /SharpSword\.exe/ nocase ascii wide
                        $string6_SharpSword_offensive_tool_keyword = /SharpSword\.sln/ nocase ascii wide
                        $string7_SharpSword_offensive_tool_keyword = /SharpSword\-main\./ nocase ascii wide

    condition:
        any of them
}