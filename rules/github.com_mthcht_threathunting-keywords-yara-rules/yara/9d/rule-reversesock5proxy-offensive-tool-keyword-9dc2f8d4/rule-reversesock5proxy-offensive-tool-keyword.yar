rule rule_ReverseSock5Proxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ReverseSock5Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReverseSock5Proxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ReverseSock5Proxy_offensive_tool_keyword = /\/ReverseSock5Proxy\.git/ nocase ascii wide
                        $string2_ReverseSock5Proxy_offensive_tool_keyword = "/ReverseSock5Proxy/tarball/" nocase ascii wide
                        $string3_ReverseSock5Proxy_offensive_tool_keyword = "/ReverseSock5Proxy/zipball/" nocase ascii wide
                        $string4_ReverseSock5Proxy_offensive_tool_keyword = /\/SOCK5Server\.cpp/ nocase ascii wide
                        $string5_ReverseSock5Proxy_offensive_tool_keyword = /\\C2Config\.ini/ nocase ascii wide
                        $string6_ReverseSock5Proxy_offensive_tool_keyword = "0fdef22052732301186410ad11b9b5f63dfed89e9a35f431b5195cc4387ac918" nocase ascii wide
                        $string7_ReverseSock5Proxy_offensive_tool_keyword = "49340cc563c7fa1b0ee0aa45f9ef1ec227713e1bc56f9c184af0323e425119c1" nocase ascii wide
                        $string8_ReverseSock5Proxy_offensive_tool_keyword = "9db2d93288d2a07ec088c5b123cac2754a0a9ea5221e784eefedf96aca886a17" nocase ascii wide
                        $string9_ReverseSock5Proxy_offensive_tool_keyword = "Application::C2Sock" nocase ascii wide
                        $string10_ReverseSock5Proxy_offensive_tool_keyword = "C2ServerThreadTerminated" nocase ascii wide
                        $string11_ReverseSock5Proxy_offensive_tool_keyword = "Coldroot Sock5 Server" nocase ascii wide
                        $string12_ReverseSock5Proxy_offensive_tool_keyword = "Coldzer0/ReverseSock5Proxy" nocase ascii wide
                        $string13_ReverseSock5Proxy_offensive_tool_keyword = /ConfigIni\:\:GetInt\(\\"\\"Server\\"\\"\,\s\\"\\"SOCK5Port\\"\\"\,\s9090\\"/ nocase ascii wide
                        $string14_ReverseSock5Proxy_offensive_tool_keyword = "d6fea46b2c10f12284b38995e9b6cee32b2122ea9ba65c00c0c3cc5eb7448e5d" nocase ascii wide
                        $string15_ReverseSock5Proxy_offensive_tool_keyword = "fa00de3a5f4f0fd4f20a4c8cac94e67c13508d45f35d19ea5e4847c2a7a48814" nocase ascii wide
                        $string16_ReverseSock5Proxy_offensive_tool_keyword = "ReverseSock5Proxy/releases/download/" nocase ascii wide
                        $string17_ReverseSock5Proxy_offensive_tool_keyword = /SendBuffer\(C2Socket/ nocase ascii wide
                        $string18_ReverseSock5Proxy_offensive_tool_keyword = /Sock5\/Sock5RServer\.h/ nocase ascii wide
                        $string19_ReverseSock5Proxy_offensive_tool_keyword = /SOCK5Server\.exe/ nocase ascii wide
                        $string20_ReverseSock5Proxy_offensive_tool_keyword = /SOCK5Server_v0\.0\.1\.zip/ nocase ascii wide

    condition:
        any of them
}