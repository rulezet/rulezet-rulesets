rule rule_zarp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'zarp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zarp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_zarp_offensive_tool_keyword = /zarp\.py/ nocase ascii wide

    condition:
        any of them
}