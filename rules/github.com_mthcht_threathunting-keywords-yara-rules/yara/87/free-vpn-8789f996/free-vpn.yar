rule Free_VPN
{
    meta:
        description = "Detection patterns for the tool 'Free VPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free VPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "jgbaghohigdbgbolncodkdlpenhcmcge" nocase ascii wide
                        $string2 = "majdfhpaihoncoakbjgbdhglocklcgno" nocase ascii wide

    condition:
        any of them
}