rule filebin_net
{
    meta:
        description = "Detection patterns for the tool 'filebin.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "filebin.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/filebin\.net\// nocase ascii wide
                        $string2 = /https\:\/\/s3\.filebin\.net\/filebin\// nocase ascii wide

    condition:
        any of them
}