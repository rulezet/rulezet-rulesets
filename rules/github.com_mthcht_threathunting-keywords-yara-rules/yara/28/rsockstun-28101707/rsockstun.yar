rule rsockstun
{
    meta:
        description = "Detection patterns for the tool 'rsockstun' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsockstun"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-listen\s\:.{0,1000}\s\-socks\s.{0,1000}\s\-cert\s.{0,1000}\s\-agentpassword\s/ nocase ascii wide
                        $string2 = /\.\/rsockstun/
                        $string3 = "/rsockstun "
                        $string4 = /\/rsockstun\.git/ nocase ascii wide
                        $string5 = "llkat/rsockstun" nocase ascii wide
                        $string6 = "RocksDefaultRequestRocksDefaultRequestRocksDefaultRequestRocks" nocase ascii wide
                        $string7 = "rsockstun -" nocase ascii wide
                        $string8 = /rsockstun\-1\.1\.zip/ nocase ascii wide
                        $string9 = "rsockstun-master" nocase ascii wide

    condition:
        any of them
}