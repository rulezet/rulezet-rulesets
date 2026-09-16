rule rule__1clickVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '1clickVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "1clickVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1__1clickVPN_greyware_tool_keyword = "fcfhplploccackoneaefokcmbjfbkenj" nocase ascii wide

    condition:
        any of them
}