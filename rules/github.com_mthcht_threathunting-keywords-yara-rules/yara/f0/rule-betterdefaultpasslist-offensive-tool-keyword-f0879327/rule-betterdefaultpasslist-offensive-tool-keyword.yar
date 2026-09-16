rule rule_betterdefaultpasslist_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'betterdefaultpasslist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "betterdefaultpasslist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_betterdefaultpasslist_offensive_tool_keyword = "betterdefaultpasslist" nocase ascii wide

    condition:
        any of them
}