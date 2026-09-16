rule FastStunnel_VPN
{
    meta:
        description = "Detection patterns for the tool 'FastStunnel VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FastStunnel VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "bblcccknbdbplgmdjnnikffefhdlobhp" nocase ascii wide

    condition:
        any of them
}