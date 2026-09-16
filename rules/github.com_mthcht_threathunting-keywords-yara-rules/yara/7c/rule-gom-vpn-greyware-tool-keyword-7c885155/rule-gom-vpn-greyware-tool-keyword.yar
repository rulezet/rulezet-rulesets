rule rule_Gom_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Gom VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gom VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Gom_VPN_greyware_tool_keyword = "ckiahbcmlmkpfiijecbpflfahoimklke" nocase ascii wide

    condition:
        any of them
}