rule rule_mitm6_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mitm6' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitm6"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mitm6_offensive_tool_keyword = "mitm6 -d "
                        $string2_mitm6_offensive_tool_keyword = /mitm6\.py/ nocase ascii wide

    condition:
        any of them
}