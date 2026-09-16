rule rule_FastStunnel_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FastStunnel VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FastStunnel VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_FastStunnel_VPN_greyware_tool_keyword = "bblcccknbdbplgmdjnnikffefhdlobhp" nocase ascii wide

    condition:
        any of them
}