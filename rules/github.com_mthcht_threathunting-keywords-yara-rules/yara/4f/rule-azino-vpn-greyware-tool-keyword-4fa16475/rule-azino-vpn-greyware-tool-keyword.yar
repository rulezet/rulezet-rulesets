rule rule_Azino_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Azino VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Azino VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Azino_VPN_greyware_tool_keyword = "iolonopooapdagdemdoaihahlfkncfgg" nocase ascii wide

    condition:
        any of them
}