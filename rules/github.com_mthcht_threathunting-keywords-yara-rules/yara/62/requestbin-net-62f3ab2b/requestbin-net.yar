rule requestbin_net
{
    meta:
        description = "Detection patterns for the tool 'requestbin.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "requestbin.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.d\.requestbin\.net/ nocase ascii wide
                        $string2 = /http\:\/\/requestbin\.net\/r\// nocase ascii wide
                        $string3 = /https\:\/\/requestbin\.net\/r\// nocase ascii wide

    condition:
        any of them
}