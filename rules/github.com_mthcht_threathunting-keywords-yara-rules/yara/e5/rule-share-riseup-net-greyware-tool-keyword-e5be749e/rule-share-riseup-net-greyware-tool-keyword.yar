rule rule_share_riseup_net_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'share.riseup.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "share.riseup.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_share_riseup_net_greyware_tool_keyword = /https\:\/\/share\.riseup\.net\/2/ nocase ascii wide
                        $string2_share_riseup_net_greyware_tool_keyword = /https\:\/\/share\.riseup\.net\/up/ nocase ascii wide

    condition:
        any of them
}