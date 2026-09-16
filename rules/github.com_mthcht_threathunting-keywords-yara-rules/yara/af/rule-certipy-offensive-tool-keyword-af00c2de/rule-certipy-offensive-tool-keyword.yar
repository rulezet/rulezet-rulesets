rule rule_Certipy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Certipy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Certipy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Certipy_offensive_tool_keyword = " certipy-ad" nocase ascii wide
                        $string2_Certipy_offensive_tool_keyword = /\s\-dns\-tcp\s\-nameserver\s.{0,1000}\s\-dc\-ip/ nocase ascii wide
                        $string3_Certipy_offensive_tool_keyword = " -no-pass -dns-tcp -nameserver" nocase ascii wide
                        $string4_Certipy_offensive_tool_keyword = " -old-bloodhound" nocase ascii wide
                        $string5_Certipy_offensive_tool_keyword = /\sshadow\sauto\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-account\s/ nocase ascii wide
                        $string6_Certipy_offensive_tool_keyword = /\.exe\sfind\s\-username\s.{0,1000}\s\-dc\-ip\s/ nocase ascii wide
                        $string7_Certipy_offensive_tool_keyword = /\/Certipy\.git/ nocase ascii wide
                        $string8_Certipy_offensive_tool_keyword = "/Certipy/" nocase ascii wide
                        $string9_Certipy_offensive_tool_keyword = /\/certipy64\.exe/ nocase ascii wide
                        $string10_Certipy_offensive_tool_keyword = /\\certipy64\.exe/ nocase ascii wide
                        $string11_Certipy_offensive_tool_keyword = "certipy account " nocase ascii wide
                        $string12_Certipy_offensive_tool_keyword = "certipy auth " nocase ascii wide
                        $string13_Certipy_offensive_tool_keyword = "certipy ca " nocase ascii wide
                        $string14_Certipy_offensive_tool_keyword = "certipy ca -backup" nocase ascii wide
                        $string15_Certipy_offensive_tool_keyword = "certipy cert " nocase ascii wide
                        $string16_Certipy_offensive_tool_keyword = "certipy find " nocase ascii wide
                        $string17_Certipy_offensive_tool_keyword = "certipy forge " nocase ascii wide
                        $string18_Certipy_offensive_tool_keyword = "certipy forge " nocase ascii wide
                        $string19_Certipy_offensive_tool_keyword = "certipy relay " nocase ascii wide
                        $string20_Certipy_offensive_tool_keyword = "certipy req " nocase ascii wide
                        $string21_Certipy_offensive_tool_keyword = "certipy shadow " nocase ascii wide
                        $string22_Certipy_offensive_tool_keyword = "certipy template " nocase ascii wide
                        $string23_Certipy_offensive_tool_keyword = /certipy\-master\.zip/ nocase ascii wide
                        $string24_Certipy_offensive_tool_keyword = "ly4k/Certipy" nocase ascii wide
                        $string25_Certipy_offensive_tool_keyword = "certipy " nocase ascii wide

    condition:
        any of them
}