rule WorkingVPN
{
    meta:
        description = "Detection patterns for the tool 'WorkingVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WorkingVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "mhngpdlhojliikfknhfaglpnddniijfh" nocase ascii wide

    condition:
        any of them
}