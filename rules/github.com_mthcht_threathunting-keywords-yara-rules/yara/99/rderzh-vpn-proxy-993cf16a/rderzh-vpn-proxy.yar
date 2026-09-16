rule rderzh_VPN_Proxy
{
    meta:
        description = "Detection patterns for the tool 'rderzh VPN Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rderzh VPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "oifjbnnafapeiknapihcmpeodaeblbkn" nocase ascii wide

    condition:
        any of them
}