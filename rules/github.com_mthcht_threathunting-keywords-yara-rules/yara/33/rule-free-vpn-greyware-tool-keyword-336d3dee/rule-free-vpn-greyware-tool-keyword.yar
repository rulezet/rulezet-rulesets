rule rule_Free_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Free_VPN_greyware_tool_keyword = "jgbaghohigdbgbolncodkdlpenhcmcge" nocase ascii wide
                        $string2_Free_VPN_greyware_tool_keyword = "majdfhpaihoncoakbjgbdhglocklcgno" nocase ascii wide

    condition:
        any of them
}