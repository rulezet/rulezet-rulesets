rule VPN_PROXY_MASTER
{
    meta:
        description = "Detection patterns for the tool 'VPN PROXY MASTER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN PROXY MASTER"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "lnfdmdhmfbimhhpaeocncdlhiodoblbd" nocase ascii wide

    condition:
        any of them
}