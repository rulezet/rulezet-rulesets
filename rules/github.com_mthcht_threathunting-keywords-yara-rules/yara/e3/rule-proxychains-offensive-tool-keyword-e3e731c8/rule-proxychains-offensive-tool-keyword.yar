rule rule_proxychains_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'proxychains' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "proxychains"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_proxychains_offensive_tool_keyword = " proxychains " nocase ascii wide
                        $string2_proxychains_offensive_tool_keyword = " -q mfsconsole" nocase ascii wide
                        $string3_proxychains_offensive_tool_keyword = "!!!need more proxies!!!" nocase ascii wide
                        $string4_proxychains_offensive_tool_keyword = /\/\.proxychains\//
                        $string5_proxychains_offensive_tool_keyword = /\/etc\/proxychains\.conf/
                        $string6_proxychains_offensive_tool_keyword = /\/proxychains\-.{0,1000}\.zip/ nocase ascii wide
                        $string7_proxychains_offensive_tool_keyword = /\/proxychains\.conf/
                        $string8_proxychains_offensive_tool_keyword = /\/proxychains\.git/ nocase ascii wide
                        $string9_proxychains_offensive_tool_keyword = "/proxychains-ng" nocase ascii wide
                        $string10_proxychains_offensive_tool_keyword = "36ddc7f64cb3df2ca4170627c6e0f0dea33d1a6d0730629dff6f5c633f2006f9" nocase ascii wide
                        $string11_proxychains_offensive_tool_keyword = "58b90ade2d52bd1436e28c1930315aa46eedd5df7ff89f4ef66554933b2792b8" nocase ascii wide
                        $string12_proxychains_offensive_tool_keyword = "a8c060ee140475c6ff0065e27e2274b37f7c3b9ba433ce2b406710b565ab078a" nocase ascii wide
                        $string13_proxychains_offensive_tool_keyword = "apt install proxychains" nocase ascii wide
                        $string14_proxychains_offensive_tool_keyword = "cc5f2e1b736d42c93cc10e7bab3004b24fe8c75ad565e1a65d3480b8bd1d1555" nocase ascii wide
                        $string15_proxychains_offensive_tool_keyword = "dea9d52d974dbe0c3598b7f75f07f6e1ef6eb835195938188942f49f9034a432" nocase ascii wide
                        $string16_proxychains_offensive_tool_keyword = "haad/proxychains" nocase ascii wide
                        $string17_proxychains_offensive_tool_keyword = "install proxychains" nocase ascii wide
                        $string18_proxychains_offensive_tool_keyword = "jianingy/proxychains" nocase ascii wide
                        $string19_proxychains_offensive_tool_keyword = "make proxychains quiet" nocase ascii wide
                        $string20_proxychains_offensive_tool_keyword = "proxychains -" nocase ascii wide
                        $string21_proxychains_offensive_tool_keyword = "proxychains cme smb" nocase ascii wide
                        $string22_proxychains_offensive_tool_keyword = "proxychains nmap" nocase ascii wide
                        $string23_proxychains_offensive_tool_keyword = "proxychains smbclient -L " nocase ascii wide
                        $string24_proxychains_offensive_tool_keyword = "proxychains ssh" nocase ascii wide
                        $string25_proxychains_offensive_tool_keyword = "proxychains telnet" nocase ascii wide
                        $string26_proxychains_offensive_tool_keyword = /proxychains\.conf/ nocase ascii wide
                        $string27_proxychains_offensive_tool_keyword = /proxychains\.lsm/ nocase ascii wide
                        $string28_proxychains_offensive_tool_keyword = /proxychains\.sourceforge\.net/ nocase ascii wide
                        $string29_proxychains_offensive_tool_keyword = "proxychains_proxy_count" nocase ascii wide
                        $string30_proxychains_offensive_tool_keyword = /proxychains4\s\-q\s.{0,1000}\ssmb\s1/
                        $string31_proxychains_offensive_tool_keyword = "proxychains4" nocase ascii wide
                        $string32_proxychains_offensive_tool_keyword = "proxychains-master" nocase ascii wide
                        $string33_proxychains_offensive_tool_keyword = /proxychains\-other\.conf/ nocase ascii wide
                        $string34_proxychains_offensive_tool_keyword = "proxyresolv " nocase ascii wide
                        $string35_proxychains_offensive_tool_keyword = "rofl0r/proxychains" nocase ascii wide
                        $string36_proxychains_offensive_tool_keyword = /socks.{0,1000}127\.0\.0\.1\s9050/ nocase ascii wide

    condition:
        any of them
}