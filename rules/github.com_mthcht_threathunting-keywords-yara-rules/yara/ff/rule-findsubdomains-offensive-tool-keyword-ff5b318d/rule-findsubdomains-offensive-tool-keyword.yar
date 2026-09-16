rule rule_findsubdomains_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'findsubdomains' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "findsubdomains"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_findsubdomains_offensive_tool_keyword = "Findsubdomains" nocase ascii wide

    condition:
        any of them
}