rule rule_goPassGen_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'goPassGen' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goPassGen"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_goPassGen_offensive_tool_keyword = /\/goPassGen\.git/ nocase ascii wide
                        $string2_goPassGen_offensive_tool_keyword = "bigb0sss/goPassGen" nocase ascii wide
                        $string3_goPassGen_offensive_tool_keyword = "goPassGen-master" nocase ascii wide

    condition:
        any of them
}