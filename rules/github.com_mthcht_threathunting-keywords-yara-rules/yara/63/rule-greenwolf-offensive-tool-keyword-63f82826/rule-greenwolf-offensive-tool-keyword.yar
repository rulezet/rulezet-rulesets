rule rule_Greenwolf_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Greenwolf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Greenwolf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Greenwolf_offensive_tool_keyword = "Greenwolf" nocase ascii wide

    condition:
        any of them
}