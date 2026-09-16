rule Certipy
{
    meta:
        description = "Detection patterns for the tool 'Certipy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Certipy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " certipy-ad" nocase ascii wide
                        $string2 = /\s\-dns\-tcp\s\-nameserver\s.{0,1000}\s\-dc\-ip/ nocase ascii wide
                        $string3 = " -no-pass -dns-tcp -nameserver" nocase ascii wide
                        $string4 = " -old-bloodhound" nocase ascii wide
                        $string5 = /\sshadow\sauto\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-account\s/ nocase ascii wide
                        $string6 = /\.exe\sfind\s\-username\s.{0,1000}\s\-dc\-ip\s/ nocase ascii wide
                        $string7 = /\/Certipy\.git/ nocase ascii wide
                        $string8 = "/Certipy/" nocase ascii wide
                        $string9 = /\/certipy64\.exe/ nocase ascii wide
                        $string10 = /\\certipy64\.exe/ nocase ascii wide
                        $string11 = "certipy account " nocase ascii wide
                        $string12 = "certipy auth " nocase ascii wide
                        $string13 = "certipy ca " nocase ascii wide
                        $string14 = "certipy ca -backup" nocase ascii wide
                        $string15 = "certipy cert " nocase ascii wide
                        $string16 = "certipy find " nocase ascii wide
                        $string17 = "certipy forge " nocase ascii wide
                        $string18 = "certipy forge " nocase ascii wide
                        $string19 = "certipy relay " nocase ascii wide
                        $string20 = "certipy req " nocase ascii wide
                        $string21 = "certipy shadow " nocase ascii wide
                        $string22 = "certipy template " nocase ascii wide
                        $string23 = /certipy\-master\.zip/ nocase ascii wide
                        $string24 = "ly4k/Certipy" nocase ascii wide
                        $string25 = "certipy " nocase ascii wide

    condition:
        any of them
}