rule rule_WitnessMe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WitnessMe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WitnessMe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WitnessMe_offensive_tool_keyword = "WitnessMe" nocase ascii wide

    condition:
        any of them
}