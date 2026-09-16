rule Hideman_VPN
{
    meta:
        description = "Detection patterns for the tool 'Hideman VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hideman VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "dbdbnchagbkhknegmhgikkleoogjcfge" nocase ascii wide

    condition:
        any of them
}