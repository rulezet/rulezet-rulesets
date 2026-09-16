rule rule_ghostsocks_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ghostsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghostsocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ghostsocks_offensive_tool_keyword = /\.ghostsocks\.json/ nocase ascii wide
                        $string2_ghostsocks_offensive_tool_keyword = /\/ghostsocks\.git/ nocase ascii wide
                        $string3_ghostsocks_offensive_tool_keyword = /\\ghostsocks\-master/ nocase ascii wide
                        $string4_ghostsocks_offensive_tool_keyword = "28625926a22131062b34670f36dafb312c2631b576bcfa0f9544994de77b6544" nocase ascii wide
                        $string5_ghostsocks_offensive_tool_keyword = "ca94d5a554af633b96f7a6b0e4b8891b4a1e30812df356f7bc21e99dbce90d8e" nocase ascii wide
                        $string6_ghostsocks_offensive_tool_keyword = "DefaultListenAddr = \":7448\"" nocase ascii wide
                        $string7_ghostsocks_offensive_tool_keyword = "ghostsocks-local" nocase ascii wide
                        $string8_ghostsocks_offensive_tool_keyword = "ghostsocks-server" nocase ascii wide
                        $string9_ghostsocks_offensive_tool_keyword = "LemonSaaS/ghostsocks" nocase ascii wide

    condition:
        any of them
}