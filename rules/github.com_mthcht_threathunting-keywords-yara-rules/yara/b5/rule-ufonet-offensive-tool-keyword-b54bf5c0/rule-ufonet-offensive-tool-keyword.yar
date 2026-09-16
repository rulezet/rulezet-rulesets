rule rule_UFONet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'UFONet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UFONet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_UFONet_offensive_tool_keyword = "UFONet" nocase ascii wide

    condition:
        any of them
}