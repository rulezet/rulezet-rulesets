rule rule_Touch_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Touch VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Touch VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Touch_VPN_greyware_tool_keyword = "bihmplhobchoageeokmgbdihknkjbknd" nocase ascii wide

    condition:
        any of them
}