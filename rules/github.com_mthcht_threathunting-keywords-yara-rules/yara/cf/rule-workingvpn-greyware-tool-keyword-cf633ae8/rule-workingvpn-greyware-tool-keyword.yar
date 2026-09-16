rule rule_WorkingVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WorkingVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WorkingVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_WorkingVPN_greyware_tool_keyword = "mhngpdlhojliikfknhfaglpnddniijfh" nocase ascii wide

    condition:
        any of them
}