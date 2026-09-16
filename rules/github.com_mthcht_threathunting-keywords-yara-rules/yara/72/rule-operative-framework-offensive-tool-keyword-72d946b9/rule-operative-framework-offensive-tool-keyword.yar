rule rule_Operative_Framework_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Operative Framework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Operative Framework"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Operative_Framework_offensive_tool_keyword = "Operative Framework" nocase ascii wide

    condition:
        any of them
}