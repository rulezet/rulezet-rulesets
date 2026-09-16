rule ThunderDNS
{
    meta:
        description = "Detection patterns for the tool 'ThunderDNS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThunderDNS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ThunderDNS" nocase ascii wide
                        $string2 = /proxy\.py\s\-\-dns\s.{0,1000}\s\-\-dns_port\s\s.{0,1000}\s\-\-clients/ nocase ascii wide
                        $string3 = /ThunderDNS.{0,1000}\.php/ nocase ascii wide
                        $string4 = /ThunderDNS.{0,1000}\.ps1/ nocase ascii wide
                        $string5 = /ThunderDNS.{0,1000}\.py/ nocase ascii wide
                        $string6 = /ThunderDNS\.git/ nocase ascii wide

    condition:
        any of them
}