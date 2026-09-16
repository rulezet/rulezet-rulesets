rule PP_VPN
{
    meta:
        description = "Detection patterns for the tool 'PP VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PP VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "jljopmgdobloagejpohpldgkiellmfnc" nocase ascii wide

    condition:
        any of them
}