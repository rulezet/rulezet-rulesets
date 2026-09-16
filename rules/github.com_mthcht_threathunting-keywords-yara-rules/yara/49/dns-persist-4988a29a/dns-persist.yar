rule DNS_Persist
{
    meta:
        description = "Detection patterns for the tool 'DNS-Persist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNS-Persist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/DNS-Persist/" nocase ascii wide
                        $string2 = "0x09AL/DNS-Persist" nocase ascii wide
                        $string3 = /agent.{0,1000}DNSCommunication\.cpp/ nocase ascii wide
                        $string4 = "DNS-C2 #>" nocase ascii wide
                        $string5 = /DNSListener\.py/ nocase ascii wide
                        $string6 = /DNS\-Persist\.git/ nocase ascii wide
                        $string7 = "do_bypassuac" nocase ascii wide
                        $string8 = "execute_shellcode " nocase ascii wide
                        $string9 = "import DNSListener" nocase ascii wide
                        $string10 = "keylog_dump" nocase ascii wide
                        $string11 = "keylog_start" nocase ascii wide
                        $string12 = "keylog_stop" nocase ascii wide
                        $string13 = "persist exceladdin" nocase ascii wide
                        $string14 = "persist logonscript" nocase ascii wide
                        $string15 = "persist runkey" nocase ascii wide
                        $string16 = /Persistence\.exe/ nocase ascii wide
                        $string17 = "Shellcode Injected Successfully" nocase ascii wide

    condition:
        any of them
}