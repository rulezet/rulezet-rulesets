rule rule_Hotspot_Shield_Free_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hotspot Shield Free VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hotspot Shield Free VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Hotspot_Shield_Free_VPN_greyware_tool_keyword = "nlbejmccbhkncgokjcmghpfloaajcffj" nocase ascii wide

    condition:
        any of them
}