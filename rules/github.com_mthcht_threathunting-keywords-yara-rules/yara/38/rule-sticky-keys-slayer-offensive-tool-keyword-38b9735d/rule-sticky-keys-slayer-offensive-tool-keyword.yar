rule rule_Sticky_Keys_Slayer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Sticky-Keys-Slayer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sticky-Keys-Slayer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Sticky_Keys_Slayer_offensive_tool_keyword = "Sticky-Keys-Slayer" nocase ascii wide

    condition:
        any of them
}