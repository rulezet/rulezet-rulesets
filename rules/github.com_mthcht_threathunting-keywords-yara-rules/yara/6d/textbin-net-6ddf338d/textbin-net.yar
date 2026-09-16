rule textbin_net
{
    meta:
        description = "Detection patterns for the tool 'textbin.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "textbin.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/textbin\.net\/raw\// nocase ascii wide

    condition:
        any of them
}