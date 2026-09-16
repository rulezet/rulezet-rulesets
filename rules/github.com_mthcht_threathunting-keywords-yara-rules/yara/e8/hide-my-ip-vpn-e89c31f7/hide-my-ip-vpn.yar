rule Hide_My_IP_VPN
{
    meta:
        description = "Detection patterns for the tool 'Hide My IP VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hide My IP VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "keodbianoliadkoelloecbhllnpiocoi" nocase ascii wide

    condition:
        any of them
}