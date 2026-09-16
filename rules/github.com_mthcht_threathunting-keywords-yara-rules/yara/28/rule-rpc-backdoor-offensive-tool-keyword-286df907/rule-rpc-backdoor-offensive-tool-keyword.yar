rule rule_RPC_Backdoor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RPC-Backdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RPC-Backdoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RPC_Backdoor_offensive_tool_keyword = /\s\-\-pipename\s.{0,1000}\\\\pipe\\\\atctl\\/ nocase ascii wide
                        $string2_RPC_Backdoor_offensive_tool_keyword = /\/RPC\-Backdoor\.git/ nocase ascii wide
                        $string3_RPC_Backdoor_offensive_tool_keyword = /\/RPC\-Backdoor_v1\.0\.7z/ nocase ascii wide
                        $string4_RPC_Backdoor_offensive_tool_keyword = /\/RPC\-Backdoor_v1\.0\.zip/ nocase ascii wide
                        $string5_RPC_Backdoor_offensive_tool_keyword = /\\RPC\sBackdoor\.sln/ nocase ascii wide
                        $string6_RPC_Backdoor_offensive_tool_keyword = /\\RPC\-Backdoor\\/ nocase ascii wide
                        $string7_RPC_Backdoor_offensive_tool_keyword = /\\RPC\-Backdoor_v1\.0\.7z/ nocase ascii wide
                        $string8_RPC_Backdoor_offensive_tool_keyword = /\\RPC\-Backdoor_v1\.0\.zip/ nocase ascii wide
                        $string9_RPC_Backdoor_offensive_tool_keyword = /\\RPC\-Backdoor\-main/ nocase ascii wide
                        $string10_RPC_Backdoor_offensive_tool_keyword = "0ABB9F2A-6913-4174-9431-851F9D3E94B4" nocase ascii wide
                        $string11_RPC_Backdoor_offensive_tool_keyword = "3C21F82B-B958-457A-82BB-B8A795316D3D" nocase ascii wide
                        $string12_RPC_Backdoor_offensive_tool_keyword = "6299009a4d05609f3960b17f3714579cd3fa4e85c2dbab240672301884fd89d5" nocase ascii wide
                        $string13_RPC_Backdoor_offensive_tool_keyword = "6536EBEC-014E-4D6B-97BE-223137694CA8" nocase ascii wide
                        $string14_RPC_Backdoor_offensive_tool_keyword = "758DB128-9123-4E1B-A6C3-47323714123A" nocase ascii wide
                        $string15_RPC_Backdoor_offensive_tool_keyword = "758DB129-9123-4E1B-A6C3-47323714123A" nocase ascii wide
                        $string16_RPC_Backdoor_offensive_tool_keyword = "7aa8e56e132d653609ccc17d76b630500443bc7b4b9a3eeba8359151d3db5961" nocase ascii wide
                        $string17_RPC_Backdoor_offensive_tool_keyword = "8558952E-C76B-4976-949F-76A977DA7F8A" nocase ascii wide
                        $string18_RPC_Backdoor_offensive_tool_keyword = "ca2aa2a0ef687163b261bba61c0b55033e9c4080bfb889e48b7e4664a2af91ed" nocase ascii wide
                        $string19_RPC_Backdoor_offensive_tool_keyword = "eladshamir/RPC-Backdoor" nocase ascii wide
                        $string20_RPC_Backdoor_offensive_tool_keyword = "net user hax0r /add" nocase ascii wide
                        $string21_RPC_Backdoor_offensive_tool_keyword = /RpcSharpClient\.exe\s\-\-protocol\snamedpipe\s/ nocase ascii wide

    condition:
        any of them
}