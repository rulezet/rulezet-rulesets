rule ipv4_myip_wtf
{
    meta:
        description = "Detection patterns for the tool 'ipv4.myip.wtf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ipv4.myip.wtf"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/ipv4\.myip\.wtf\/text/ nocase ascii wide

    condition:
        any of them
}