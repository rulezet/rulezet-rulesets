rule proxychains
{
    meta:
        description = "Detection patterns for the tool 'proxychains' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "proxychains"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " proxychains " nocase ascii wide
                        $string2 = " -q mfsconsole" nocase ascii wide
                        $string3 = "!!!need more proxies!!!" nocase ascii wide
                        $string4 = /\/\.proxychains\//
                        $string5 = /\/etc\/proxychains\.conf/
                        $string6 = /\/proxychains\-.{0,1000}\.zip/ nocase ascii wide
                        $string7 = /\/proxychains\.conf/
                        $string8 = /\/proxychains\.git/ nocase ascii wide
                        $string9 = "/proxychains-ng" nocase ascii wide
                        $string10 = "36ddc7f64cb3df2ca4170627c6e0f0dea33d1a6d0730629dff6f5c633f2006f9" nocase ascii wide
                        $string11 = "58b90ade2d52bd1436e28c1930315aa46eedd5df7ff89f4ef66554933b2792b8" nocase ascii wide
                        $string12 = "a8c060ee140475c6ff0065e27e2274b37f7c3b9ba433ce2b406710b565ab078a" nocase ascii wide
                        $string13 = "apt install proxychains" nocase ascii wide
                        $string14 = "cc5f2e1b736d42c93cc10e7bab3004b24fe8c75ad565e1a65d3480b8bd1d1555" nocase ascii wide
                        $string15 = "dea9d52d974dbe0c3598b7f75f07f6e1ef6eb835195938188942f49f9034a432" nocase ascii wide
                        $string16 = "haad/proxychains" nocase ascii wide
                        $string17 = "install proxychains" nocase ascii wide
                        $string18 = "jianingy/proxychains" nocase ascii wide
                        $string19 = "make proxychains quiet" nocase ascii wide
                        $string20 = "proxychains -" nocase ascii wide
                        $string21 = "proxychains cme smb" nocase ascii wide
                        $string22 = "proxychains nmap" nocase ascii wide
                        $string23 = "proxychains smbclient -L " nocase ascii wide
                        $string24 = "proxychains ssh" nocase ascii wide
                        $string25 = "proxychains telnet" nocase ascii wide
                        $string26 = /proxychains\.conf/ nocase ascii wide
                        $string27 = /proxychains\.lsm/ nocase ascii wide
                        $string28 = /proxychains\.sourceforge\.net/ nocase ascii wide
                        $string29 = "proxychains_proxy_count" nocase ascii wide
                        $string30 = /proxychains4\s\-q\s.{0,1000}\ssmb\s1/
                        $string31 = "proxychains4" nocase ascii wide
                        $string32 = "proxychains-master" nocase ascii wide
                        $string33 = /proxychains\-other\.conf/ nocase ascii wide
                        $string34 = "proxyresolv " nocase ascii wide
                        $string35 = "rofl0r/proxychains" nocase ascii wide
                        $string36 = /socks.{0,1000}127\.0\.0\.1\s9050/ nocase ascii wide

    condition:
        any of them
}