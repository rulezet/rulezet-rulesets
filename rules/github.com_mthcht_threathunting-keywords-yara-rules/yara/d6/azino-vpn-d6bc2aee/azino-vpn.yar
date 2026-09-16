rule Azino_VPN
{
    meta:
        description = "Detection patterns for the tool 'Azino VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Azino VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "iolonopooapdagdemdoaihahlfkncfgg" nocase ascii wide

    condition:
        any of them
}