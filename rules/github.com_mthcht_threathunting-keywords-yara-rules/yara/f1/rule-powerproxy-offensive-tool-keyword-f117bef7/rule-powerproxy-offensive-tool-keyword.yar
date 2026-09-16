rule rule_PowerProxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerProxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerProxy_offensive_tool_keyword = /\/PowerProxy\.git/ nocase ascii wide
                        $string2_PowerProxy_offensive_tool_keyword = /\/PowerProxy\.ps1/ nocase ascii wide
                        $string3_PowerProxy_offensive_tool_keyword = /\\PowerProxy\.ps1/ nocase ascii wide
                        $string4_PowerProxy_offensive_tool_keyword = "c0c309f54e29865152bf4ffacf5dd7084e33dd67ee139d33e27efd6628833813" nocase ascii wide
                        $string5_PowerProxy_offensive_tool_keyword = "Fuck off, no GSSAPI" nocase ascii wide
                        $string6_PowerProxy_offensive_tool_keyword = "get-get-get-get/PowerProxy" nocase ascii wide
                        $string7_PowerProxy_offensive_tool_keyword = "Invoke-ReverseProxy" nocase ascii wide
                        $string8_PowerProxy_offensive_tool_keyword = "Invoke-ReverseSocksProxy" nocase ascii wide
                        $string9_PowerProxy_offensive_tool_keyword = "Start-ReverseSocksProxy " nocase ascii wide

    condition:
        any of them
}