rule rule_smbcrawler_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'smbcrawler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smbcrawler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_smbcrawler_offensive_tool_keyword = /impacket\.smbconnection/ nocase ascii wide
                        $string2_smbcrawler_offensive_tool_keyword = "smbcrawler" nocase ascii wide

    condition:
        any of them
}