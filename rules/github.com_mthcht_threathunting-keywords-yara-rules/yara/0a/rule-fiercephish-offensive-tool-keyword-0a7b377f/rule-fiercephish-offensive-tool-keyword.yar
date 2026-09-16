rule rule_FiercePhish_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FiercePhish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FiercePhish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FiercePhish_offensive_tool_keyword = "FiercePhish" nocase ascii wide

    condition:
        any of them
}