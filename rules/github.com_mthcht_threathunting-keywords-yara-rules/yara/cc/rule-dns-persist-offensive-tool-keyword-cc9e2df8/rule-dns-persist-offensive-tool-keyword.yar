rule rule_DNS_Persist_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DNS-Persist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNS-Persist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DNS_Persist_offensive_tool_keyword = "/DNS-Persist/" nocase ascii wide
                        $string2_DNS_Persist_offensive_tool_keyword = "0x09AL/DNS-Persist" nocase ascii wide
                        $string3_DNS_Persist_offensive_tool_keyword = /agent.{0,1000}DNSCommunication\.cpp/ nocase ascii wide
                        $string4_DNS_Persist_offensive_tool_keyword = "DNS-C2 #>" nocase ascii wide
                        $string5_DNS_Persist_offensive_tool_keyword = /DNSListener\.py/ nocase ascii wide
                        $string6_DNS_Persist_offensive_tool_keyword = /DNS\-Persist\.git/ nocase ascii wide
                        $string7_DNS_Persist_offensive_tool_keyword = "do_bypassuac" nocase ascii wide
                        $string8_DNS_Persist_offensive_tool_keyword = "execute_shellcode " nocase ascii wide
                        $string9_DNS_Persist_offensive_tool_keyword = "import DNSListener" nocase ascii wide
                        $string10_DNS_Persist_offensive_tool_keyword = "keylog_dump" nocase ascii wide
                        $string11_DNS_Persist_offensive_tool_keyword = "keylog_start" nocase ascii wide
                        $string12_DNS_Persist_offensive_tool_keyword = "keylog_stop" nocase ascii wide
                        $string13_DNS_Persist_offensive_tool_keyword = "persist exceladdin" nocase ascii wide
                        $string14_DNS_Persist_offensive_tool_keyword = "persist logonscript" nocase ascii wide
                        $string15_DNS_Persist_offensive_tool_keyword = "persist runkey" nocase ascii wide
                        $string16_DNS_Persist_offensive_tool_keyword = /Persistence\.exe/ nocase ascii wide
                        $string17_DNS_Persist_offensive_tool_keyword = "Shellcode Injected Successfully" nocase ascii wide

    condition:
        any of them
}