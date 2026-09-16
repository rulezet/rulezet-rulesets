rule rule_C2ReverseProxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'C2ReverseProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2ReverseProxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_C2ReverseProxy_offensive_tool_keyword = /\/C2ReverseProxy\.git/ nocase ascii wide
                        $string2_C2ReverseProxy_offensive_tool_keyword = "/C2ReverseProxy/" nocase ascii wide
                        $string3_C2ReverseProxy_offensive_tool_keyword = "/C2ReverseProxy/tarball" nocase ascii wide
                        $string4_C2ReverseProxy_offensive_tool_keyword = "/C2ReverseProxy/zipball" nocase ascii wide
                        $string5_C2ReverseProxy_offensive_tool_keyword = "/C2ReverseServer" nocase ascii wide
                        $string6_C2ReverseProxy_offensive_tool_keyword = /\/DReverseProxy\.git/ nocase ascii wide
                        $string7_C2ReverseProxy_offensive_tool_keyword = /\\C2ReverseProxy\\/ nocase ascii wide
                        $string8_C2ReverseProxy_offensive_tool_keyword = /\\C2ReverseServer/ nocase ascii wide
                        $string9_C2ReverseProxy_offensive_tool_keyword = /\\C2script\\.{0,1000}\.ashx/ nocase ascii wide
                        $string10_C2ReverseProxy_offensive_tool_keyword = /\\C2script\\.{0,1000}\.jsp/ nocase ascii wide
                        $string11_C2ReverseProxy_offensive_tool_keyword = /\\C2script\\.{0,1000}\.php/ nocase ascii wide
                        $string12_C2ReverseProxy_offensive_tool_keyword = /\\DReverseClint\.go/ nocase ascii wide
                        $string13_C2ReverseProxy_offensive_tool_keyword = /\\DReverseServer\.go/ nocase ascii wide
                        $string14_C2ReverseProxy_offensive_tool_keyword = "0c3379e3cc4fab5cbf1ce0aff52559da191a2b97c6fa27d5122232649f78e7cc" nocase ascii wide
                        $string15_C2ReverseProxy_offensive_tool_keyword = "512e079176dfe039a4692927ad7fbe518c944c28bb434add1118fef88a48029c" nocase ascii wide
                        $string16_C2ReverseProxy_offensive_tool_keyword = "a0595728f0d3fbcc2cb434ad9af104158c349cc05a360e037ee027529bde97d1" nocase ascii wide
                        $string17_C2ReverseProxy_offensive_tool_keyword = /c2\starget\,eg\s127\.0\.0\.1\:64535/ nocase ascii wide
                        $string18_C2ReverseProxy_offensive_tool_keyword = "Daybr4ak/C2ReverseProxy" nocase ascii wide
                        $string19_C2ReverseProxy_offensive_tool_keyword = "f2c1234d05744b49749b6ef743d7a71a45d96400ec1b510531032de8312a377d" nocase ascii wide
                        $string20_C2ReverseProxy_offensive_tool_keyword = "f94f938826dab5d26488e0bc6f5aa8e9eed3a395d1e9a0c9f2a49d877ea56225" nocase ascii wide
                        $string21_C2ReverseProxy_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\/proxy\.php/ nocase ascii wide

    condition:
        any of them
}