rule rule_dnslog_cn_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnslog.cn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnslog.cn"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_dnslog_cn_greyware_tool_keyword = /\.dnslog\.cn\:/ nocase ascii wide
                        $string2_dnslog_cn_greyware_tool_keyword = /http\:\/\/dnslog\.cn\// nocase ascii wide

    condition:
        any of them
}