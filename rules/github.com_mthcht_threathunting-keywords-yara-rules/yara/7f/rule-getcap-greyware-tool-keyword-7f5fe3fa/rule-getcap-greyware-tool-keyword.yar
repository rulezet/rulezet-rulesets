rule rule_Getcap_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Getcap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Getcap"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Getcap_greyware_tool_keyword = "getcap -r / 2>/dev/null" nocase ascii wide

    condition:
        any of them
}