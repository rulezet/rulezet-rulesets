rule rule_wpaf_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wpaf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wpaf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wpaf_offensive_tool_keyword = /\/wpaf\/finder\.py/
                        $string2_wpaf_offensive_tool_keyword = "kancotdiq/wpaf" nocase ascii wide

    condition:
        any of them
}