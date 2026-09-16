rule rule_catphish_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'catphish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "catphish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_catphish_offensive_tool_keyword = /catphish\.rb/ nocase ascii wide

    condition:
        any of them
}