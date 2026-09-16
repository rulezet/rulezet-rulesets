rule rule_Browser_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Browser VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Browser_VPN_greyware_tool_keyword = "jdgilggpfmjpbodmhndmhojklgfdlhob" nocase ascii wide

    condition:
        any of them
}