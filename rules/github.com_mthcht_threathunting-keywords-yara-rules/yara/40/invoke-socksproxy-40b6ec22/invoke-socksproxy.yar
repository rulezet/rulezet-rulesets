rule Invoke_SocksProxy
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SocksProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SocksProxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sproxyTunnel\.ps1/ nocase ascii wide
                        $string2 = /\/Invoke\-SocksProxy\.git/ nocase ascii wide
                        $string3 = "/Invoke-SocksProxy/" nocase ascii wide
                        $string4 = /\/proxyTunnel\.ps1/ nocase ascii wide
                        $string5 = /\\Invoke\-SocksProxy\\/ nocase ascii wide
                        $string6 = /\\proxyTunnel\.ps1/ nocase ascii wide
                        $string7 = "509e8855fc2ebcd22bd352a34ef1a0493c4cf10b488b5b2d2fece7ad168518f9" nocase ascii wide
                        $string8 = "-Command \"New-NetFirewallRule -DisplayName 'Windows Update' -Direction Outbound -Action Allow" nocase ascii wide
                        $string9 = "e7697645f36de5978c1b640b6b3fc819e55b00ee8d9e9798919c11cc7a6fc88b" nocase ascii wide
                        $string10 = "Invoke-ReverseSocksProxy" nocase ascii wide
                        $string11 = "Invoke-SocksProxy " nocase ascii wide
                        $string12 = /Invoke\-SocksProxy\.psm1/ nocase ascii wide
                        $string13 = "New-NetFirewallRule -DisplayName 'Windows Update' -Direction Outbound -Action Allow" nocase ascii wide
                        $string14 = "p3nt4/Invoke-SocksProxy" nocase ascii wide
                        $string15 = /ReverseSocksProxyHandler\.py/ nocase ascii wide

    condition:
        any of them
}