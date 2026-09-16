rule rule_ThunderDNS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ThunderDNS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThunderDNS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ThunderDNS_offensive_tool_keyword = "/ThunderDNS" nocase ascii wide
                        $string2_ThunderDNS_offensive_tool_keyword = /proxy\.py\s\-\-dns\s.{0,1000}\s\-\-dns_port\s\s.{0,1000}\s\-\-clients/ nocase ascii wide
                        $string3_ThunderDNS_offensive_tool_keyword = /ThunderDNS.{0,1000}\.php/ nocase ascii wide
                        $string4_ThunderDNS_offensive_tool_keyword = /ThunderDNS.{0,1000}\.ps1/ nocase ascii wide
                        $string5_ThunderDNS_offensive_tool_keyword = /ThunderDNS.{0,1000}\.py/ nocase ascii wide
                        $string6_ThunderDNS_offensive_tool_keyword = /ThunderDNS\.git/ nocase ascii wide

    condition:
        any of them
}