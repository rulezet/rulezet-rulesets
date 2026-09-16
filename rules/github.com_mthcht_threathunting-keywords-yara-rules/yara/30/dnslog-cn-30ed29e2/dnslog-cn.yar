rule dnslog_cn
{
    meta:
        description = "Detection patterns for the tool 'dnslog.cn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnslog.cn"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.dnslog\.cn\:/ nocase ascii wide
                        $string2 = /http\:\/\/dnslog\.cn\// nocase ascii wide

    condition:
        any of them
}