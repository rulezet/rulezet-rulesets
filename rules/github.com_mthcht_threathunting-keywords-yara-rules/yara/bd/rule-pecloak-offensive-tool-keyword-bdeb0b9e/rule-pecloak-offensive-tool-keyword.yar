rule rule_peCloak_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'peCloak' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "peCloak"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_peCloak_offensive_tool_keyword = "peCloak" nocase ascii wide

    condition:
        any of them
}