rule rule_Pachine_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Pachine' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pachine"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Pachine_offensive_tool_keyword = /\s\-dc\-host\s.{0,1000}\s\-spn\s.{0,1000}\s\-impersonate\s/ nocase ascii wide
                        $string2_Pachine_offensive_tool_keyword = /\.\/pachine\.py/
                        $string3_Pachine_offensive_tool_keyword = "/ly4k/Pachine" nocase ascii wide
                        $string4_Pachine_offensive_tool_keyword = /python.{0,1000}\spachine\.py/ nocase ascii wide

    condition:
        any of them
}