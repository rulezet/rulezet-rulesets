rule Nucleus_VPN
{
    meta:
        description = "Detection patterns for the tool 'Nucleus VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nucleus VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "ffhhkmlgedgcliajaedapkdfigdobcif" nocase ascii wide

    condition:
        any of them
}