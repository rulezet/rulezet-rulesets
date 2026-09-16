rule Free_One_Touch_VPN
{
    meta:
        description = "Detection patterns for the tool 'Free One Touch VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free One Touch VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "inligpkjkhbpifecbdjhmdpcfhnlelja" nocase ascii wide

    condition:
        any of them
}