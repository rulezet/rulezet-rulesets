rule rule_katoolin3_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'katoolin3' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "katoolin3"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_katoolin3_offensive_tool_keyword = "/katoolin3"
                        $string2_katoolin3_offensive_tool_keyword = "/s-h-3-l-l/"
                        $string3_katoolin3_offensive_tool_keyword = "cd katoolin3"
                        $string4_katoolin3_offensive_tool_keyword = /katoolin.{0,1000}toollist\.py/
                        $string5_katoolin3_offensive_tool_keyword = /katoolin3\.py/

    condition:
        any of them
}