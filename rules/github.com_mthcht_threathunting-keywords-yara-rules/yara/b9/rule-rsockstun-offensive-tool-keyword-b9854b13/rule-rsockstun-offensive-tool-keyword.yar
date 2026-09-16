rule rule_rsockstun_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rsockstun' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsockstun"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rsockstun_offensive_tool_keyword = /\s\-listen\s\:.{0,1000}\s\-socks\s.{0,1000}\s\-cert\s.{0,1000}\s\-agentpassword\s/ nocase ascii wide
                        $string2_rsockstun_offensive_tool_keyword = /\.\/rsockstun/
                        $string3_rsockstun_offensive_tool_keyword = "/rsockstun "
                        $string4_rsockstun_offensive_tool_keyword = /\/rsockstun\.git/ nocase ascii wide
                        $string5_rsockstun_offensive_tool_keyword = "llkat/rsockstun" nocase ascii wide
                        $string6_rsockstun_offensive_tool_keyword = "RocksDefaultRequestRocksDefaultRequestRocksDefaultRequestRocks" nocase ascii wide
                        $string7_rsockstun_offensive_tool_keyword = "rsockstun -" nocase ascii wide
                        $string8_rsockstun_offensive_tool_keyword = /rsockstun\-1\.1\.zip/ nocase ascii wide
                        $string9_rsockstun_offensive_tool_keyword = "rsockstun-master" nocase ascii wide

    condition:
        any of them
}