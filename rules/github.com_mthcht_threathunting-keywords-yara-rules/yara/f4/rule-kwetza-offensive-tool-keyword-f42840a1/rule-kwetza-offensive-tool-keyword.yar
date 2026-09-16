rule rule_kwetza_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'kwetza' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kwetza"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_kwetza_offensive_tool_keyword = "sensepost/kwetza" nocase ascii wide

    condition:
        any of them
}