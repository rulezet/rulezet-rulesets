rule rule_warberry_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'warberry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "warberry"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_warberry_offensive_tool_keyword = "warberry" nocase ascii wide

    condition:
        any of them
}