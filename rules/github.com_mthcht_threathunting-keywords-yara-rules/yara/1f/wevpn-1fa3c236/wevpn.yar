rule WeVPN
{
    meta:
        description = "Detection patterns for the tool 'WeVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WeVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "ehbhfpfdkmhcpaehaooegfdflljcnfec" nocase ascii wide

    condition:
        any of them
}