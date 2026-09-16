rule rule_requestbin_net_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'requestbin.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "requestbin.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_requestbin_net_greyware_tool_keyword = /\.d\.requestbin\.net/ nocase ascii wide
                        $string2_requestbin_net_greyware_tool_keyword = /http\:\/\/requestbin\.net\/r\// nocase ascii wide
                        $string3_requestbin_net_greyware_tool_keyword = /https\:\/\/requestbin\.net\/r\// nocase ascii wide

    condition:
        any of them
}