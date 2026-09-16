rule dns2tcp
{
    meta:
        description = "Detection patterns for the tool 'dns2tcp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns2tcp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.dns2tcpdrc/ nocase ascii wide
                        $string2 = /\/\.dns2tcprc/
                        $string3 = "/debian/dns2tcp"
                        $string4 = /\/dns2tcp\.git/ nocase ascii wide
                        $string5 = "/dns2tcp/client/"
                        $string6 = "/dns2tcp/common/"
                        $string7 = "/dns2tcp/server"
                        $string8 = "/root/dns2tcp"
                        $string9 = /\\\\\.\\pipe\\win\-sux\-no\-async\-anon\-pipe\-.{0,1000}\-/ nocase ascii wide
                        $string10 = /\\dns2tcp\\/ nocase ascii wide
                        $string11 = /\\dns2tcp\\server/ nocase ascii wide
                        $string12 = /\\dns2tcp\-0\./ nocase ascii wide
                        $string13 = "alex-sector/dns2tcp" nocase ascii wide
                        $string14 = "apt install dns2tcp" nocase ascii wide
                        $string15 = /dns2tcp\-.{0,1000}\.zip/ nocase ascii wide
                        $string16 = /dns2tcp\.exe/ nocase ascii wide
                        $string17 = /dns2tcp\.hsc\.fr/ nocase ascii wide
                        $string18 = /dns2tcp\.kali\.org/ nocase ascii wide
                        $string19 = /dns2tcp\.pid/ nocase ascii wide
                        $string20 = "dns2tcpc -z " nocase ascii wide
                        $string21 = /dns2tcpc\.exe/ nocase ascii wide
                        $string22 = "dns2tcpd --" nocase ascii wide
                        $string23 = "dns2tcpd -f " nocase ascii wide
                        $string24 = "dns2tcp-master" nocase ascii wide

    condition:
        any of them
}