rule PowerProxy
{
    meta:
        description = "Detection patterns for the tool 'PowerProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerProxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PowerProxy\.git/ nocase ascii wide
                        $string2 = /\/PowerProxy\.ps1/ nocase ascii wide
                        $string3 = /\\PowerProxy\.ps1/ nocase ascii wide
                        $string4 = "c0c309f54e29865152bf4ffacf5dd7084e33dd67ee139d33e27efd6628833813" nocase ascii wide
                        $string5 = "Fuck off, no GSSAPI" nocase ascii wide
                        $string6 = "get-get-get-get/PowerProxy" nocase ascii wide
                        $string7 = "Invoke-ReverseProxy" nocase ascii wide
                        $string8 = "Invoke-ReverseSocksProxy" nocase ascii wide
                        $string9 = "Start-ReverseSocksProxy " nocase ascii wide

    condition:
        any of them
}