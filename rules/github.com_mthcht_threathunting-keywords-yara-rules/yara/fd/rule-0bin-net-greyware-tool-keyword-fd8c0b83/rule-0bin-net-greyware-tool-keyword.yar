rule rule__0bin_net_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '0bin.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "0bin.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1__0bin_net_greyware_tool_keyword = "0bin - encrypted pastebin" nocase ascii wide
                        $string2__0bin_net_greyware_tool_keyword = "A client side encrypted PasteBin" nocase ascii wide
                        $string3__0bin_net_greyware_tool_keyword = /https\:\/\/0bin\.net\/paste\/.{0,1000}\+/ nocase ascii wide
                        $string4__0bin_net_greyware_tool_keyword = /https\:\/\/0bin\.net\/paste\/create/ nocase ascii wide

    condition:
        any of them
}