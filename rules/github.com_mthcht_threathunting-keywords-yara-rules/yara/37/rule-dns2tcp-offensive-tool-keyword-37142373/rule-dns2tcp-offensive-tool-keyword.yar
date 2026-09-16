rule rule_dns2tcp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dns2tcp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns2tcp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dns2tcp_offensive_tool_keyword = /\.dns2tcpdrc/ nocase ascii wide
                        $string2_dns2tcp_offensive_tool_keyword = /\/\.dns2tcprc/
                        $string3_dns2tcp_offensive_tool_keyword = "/debian/dns2tcp"
                        $string4_dns2tcp_offensive_tool_keyword = /\/dns2tcp\.git/ nocase ascii wide
                        $string5_dns2tcp_offensive_tool_keyword = "/dns2tcp/client/"
                        $string6_dns2tcp_offensive_tool_keyword = "/dns2tcp/common/"
                        $string7_dns2tcp_offensive_tool_keyword = "/dns2tcp/server"
                        $string8_dns2tcp_offensive_tool_keyword = "/root/dns2tcp"
                        $string9_dns2tcp_offensive_tool_keyword = /\\\\\.\\pipe\\win\-sux\-no\-async\-anon\-pipe\-.{0,1000}\-/ nocase ascii wide
                        $string10_dns2tcp_offensive_tool_keyword = /\\dns2tcp\\/ nocase ascii wide
                        $string11_dns2tcp_offensive_tool_keyword = /\\dns2tcp\\server/ nocase ascii wide
                        $string12_dns2tcp_offensive_tool_keyword = /\\dns2tcp\-0\./ nocase ascii wide
                        $string13_dns2tcp_offensive_tool_keyword = "alex-sector/dns2tcp" nocase ascii wide
                        $string14_dns2tcp_offensive_tool_keyword = "apt install dns2tcp" nocase ascii wide
                        $string15_dns2tcp_offensive_tool_keyword = /dns2tcp\-.{0,1000}\.zip/ nocase ascii wide
                        $string16_dns2tcp_offensive_tool_keyword = /dns2tcp\.exe/ nocase ascii wide
                        $string17_dns2tcp_offensive_tool_keyword = /dns2tcp\.hsc\.fr/ nocase ascii wide
                        $string18_dns2tcp_offensive_tool_keyword = /dns2tcp\.kali\.org/ nocase ascii wide
                        $string19_dns2tcp_offensive_tool_keyword = /dns2tcp\.pid/ nocase ascii wide
                        $string20_dns2tcp_offensive_tool_keyword = "dns2tcpc -z " nocase ascii wide
                        $string21_dns2tcp_offensive_tool_keyword = /dns2tcpc\.exe/ nocase ascii wide
                        $string22_dns2tcp_offensive_tool_keyword = "dns2tcpd --" nocase ascii wide
                        $string23_dns2tcp_offensive_tool_keyword = "dns2tcpd -f " nocase ascii wide
                        $string24_dns2tcp_offensive_tool_keyword = "dns2tcp-master" nocase ascii wide

    condition:
        any of them
}