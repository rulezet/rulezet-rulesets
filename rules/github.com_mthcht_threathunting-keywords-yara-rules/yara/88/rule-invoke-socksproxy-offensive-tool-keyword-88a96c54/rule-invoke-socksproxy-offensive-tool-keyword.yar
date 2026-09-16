rule rule_Invoke_SocksProxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SocksProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SocksProxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_SocksProxy_offensive_tool_keyword = /\sproxyTunnel\.ps1/ nocase ascii wide
                        $string2_Invoke_SocksProxy_offensive_tool_keyword = /\/Invoke\-SocksProxy\.git/ nocase ascii wide
                        $string3_Invoke_SocksProxy_offensive_tool_keyword = "/Invoke-SocksProxy/" nocase ascii wide
                        $string4_Invoke_SocksProxy_offensive_tool_keyword = /\/proxyTunnel\.ps1/ nocase ascii wide
                        $string5_Invoke_SocksProxy_offensive_tool_keyword = /\\Invoke\-SocksProxy\\/ nocase ascii wide
                        $string6_Invoke_SocksProxy_offensive_tool_keyword = /\\proxyTunnel\.ps1/ nocase ascii wide
                        $string7_Invoke_SocksProxy_offensive_tool_keyword = "509e8855fc2ebcd22bd352a34ef1a0493c4cf10b488b5b2d2fece7ad168518f9" nocase ascii wide
                        $string8_Invoke_SocksProxy_offensive_tool_keyword = "-Command \"New-NetFirewallRule -DisplayName 'Windows Update' -Direction Outbound -Action Allow" nocase ascii wide
                        $string9_Invoke_SocksProxy_offensive_tool_keyword = "e7697645f36de5978c1b640b6b3fc819e55b00ee8d9e9798919c11cc7a6fc88b" nocase ascii wide
                        $string10_Invoke_SocksProxy_offensive_tool_keyword = "Invoke-ReverseSocksProxy" nocase ascii wide
                        $string11_Invoke_SocksProxy_offensive_tool_keyword = "Invoke-SocksProxy " nocase ascii wide
                        $string12_Invoke_SocksProxy_offensive_tool_keyword = /Invoke\-SocksProxy\.psm1/ nocase ascii wide
                        $string13_Invoke_SocksProxy_offensive_tool_keyword = "New-NetFirewallRule -DisplayName 'Windows Update' -Direction Outbound -Action Allow" nocase ascii wide
                        $string14_Invoke_SocksProxy_offensive_tool_keyword = "p3nt4/Invoke-SocksProxy" nocase ascii wide
                        $string15_Invoke_SocksProxy_offensive_tool_keyword = /ReverseSocksProxyHandler\.py/ nocase ascii wide

    condition:
        any of them
}