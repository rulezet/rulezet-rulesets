rule Guru_VPN__and__Proxy
{
    meta:
        description = "Detection patterns for the tool 'Guru VPN & Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Guru VPN & Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "knajdeaocbpmfghhmijicidfcmdgbdpm" nocase ascii wide

    condition:
        any of them
}