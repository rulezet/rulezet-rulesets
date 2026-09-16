rule rule_Suborner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Suborner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Suborner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Suborner_offensive_tool_keyword = /\/Suborner\.git/ nocase ascii wide
                        $string2_Suborner_offensive_tool_keyword = /\\Suborner\.sln/ nocase ascii wide
                        $string3_Suborner_offensive_tool_keyword = "r4wd3r/Suborner" nocase ascii wide
                        $string4_Suborner_offensive_tool_keyword = /Suborner\.exe/ nocase ascii wide
                        $string5_Suborner_offensive_tool_keyword = /Suborner\-master\.zip/ nocase ascii wide

    condition:
        any of them
}