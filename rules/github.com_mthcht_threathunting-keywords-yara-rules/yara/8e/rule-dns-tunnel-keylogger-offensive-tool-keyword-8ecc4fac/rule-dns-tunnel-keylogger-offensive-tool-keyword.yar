rule rule_DNS_Tunnel_Keylogger_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DNS-Tunnel-Keylogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNS-Tunnel-Keylogger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DNS_Tunnel_Keylogger_offensive_tool_keyword = /\.\/logger\.sh\s.{0,1000}\s\&\>\s\/dev\/null\s\&\&\sexit/
                        $string2_DNS_Tunnel_Keylogger_offensive_tool_keyword = "1fc325f3-c548-43db-a13f-8c460dda8381" nocase ascii wide
                        $string3_DNS_Tunnel_Keylogger_offensive_tool_keyword = "4cc3c88b175e7c6c9e881707ab3a6b956c7cbcb69a5f61d417d4736f054677b4" nocase ascii wide
                        $string4_DNS_Tunnel_Keylogger_offensive_tool_keyword = "920021c608185f95a4100ebec9e7c0fb4c67c1d192257ba9ac3430b2939762a3" nocase ascii wide
                        $string5_DNS_Tunnel_Keylogger_offensive_tool_keyword = "c4e9806596b8e6123a595395b0efe604176dfd2e767418fe4adf69c70de557b5" nocase ascii wide
                        $string6_DNS_Tunnel_Keylogger_offensive_tool_keyword = "DNS-Tunnel-Keylogger" nocase ascii wide

    condition:
        any of them
}