rule rule_BetterBackdoor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BetterBackdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BetterBackdoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BetterBackdoor_offensive_tool_keyword = "BetterBackdoor" nocase ascii wide

    condition:
        any of them
}