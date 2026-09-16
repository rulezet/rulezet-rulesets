rule rule_luckystrike_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'luckystrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "luckystrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_luckystrike_offensive_tool_keyword = /luckystrike\.ps1/ nocase ascii wide

    condition:
        any of them
}