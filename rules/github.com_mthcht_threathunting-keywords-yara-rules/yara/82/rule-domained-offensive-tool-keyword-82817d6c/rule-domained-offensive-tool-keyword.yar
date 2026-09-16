rule rule_domained_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'domained' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "domained"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_domained_offensive_tool_keyword = "TypeError/domained" nocase ascii wide

    condition:
        any of them
}