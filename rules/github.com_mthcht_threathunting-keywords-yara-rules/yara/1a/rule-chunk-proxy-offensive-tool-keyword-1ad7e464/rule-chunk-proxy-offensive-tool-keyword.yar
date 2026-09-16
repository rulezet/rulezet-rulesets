rule rule_chunk_Proxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chunk-Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chunk-Proxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_chunk_Proxy_offensive_tool_keyword = /\/Chunk\-Proxy\.git/ nocase ascii wide
                        $string2_chunk_Proxy_offensive_tool_keyword = /\/ChunkProxyHandler\.class/ nocase ascii wide
                        $string3_chunk_Proxy_offensive_tool_keyword = /\/MiTM\.java/ nocase ascii wide
                        $string4_chunk_Proxy_offensive_tool_keyword = /\\MiTM\.java/ nocase ascii wide
                        $string5_chunk_Proxy_offensive_tool_keyword = "149c0f553685f985a2eb714d9dcc54541423e57b4aecea5f2bdb747dfb9cc06d" nocase ascii wide
                        $string6_chunk_Proxy_offensive_tool_keyword = "3a3d9e54afc72d136525dc4e70bb97d5ec2f7c1d3fe2e3afe1d9a430f68b78af" nocase ascii wide
                        $string7_chunk_Proxy_offensive_tool_keyword = "84fc3746ff1c1b3bd069bc4f64bf5416b9151d980088cd902799d7997f5b3882" nocase ascii wide
                        $string8_chunk_Proxy_offensive_tool_keyword = "ae094ee177fac926d832755352a3d0fff4804e513cefc430d5987936ff493b92" nocase ascii wide
                        $string9_chunk_Proxy_offensive_tool_keyword = "b75be6d2ff15abf81ac056295c5a397177de01718d05bba61e5abc025d9977f9" nocase ascii wide
                        $string10_chunk_Proxy_offensive_tool_keyword = "BeichenDream/Chunk-Proxy" nocase ascii wide
                        $string11_chunk_Proxy_offensive_tool_keyword = "cc83886b15c006d0b3650f3327bf0264df635e6d11a3dd46680c8314bc6bd4f5" nocase ascii wide
                        $string12_chunk_Proxy_offensive_tool_keyword = /chunk\-Proxy\.jar/ nocase ascii wide
                        $string13_chunk_Proxy_offensive_tool_keyword = "f273248a26cf21cef5c0f1288f90b5aef915b477c81eb62949ab4e519b4b604b" nocase ascii wide
                        $string14_chunk_Proxy_offensive_tool_keyword = /http\:\/\/localhost\:42969\/easy\.aspx/ nocase ascii wide
                        $string15_chunk_Proxy_offensive_tool_keyword = /java\s\-jar\schunk\-Proxy\.jar\sjava\s1088\shttp\:\/\/10\.10\.10\.1\:8080\/proxy\.jsp/ nocase ascii wide
                        $string16_chunk_Proxy_offensive_tool_keyword = /java\-socks\-proxy\-server\.jar/ nocase ascii wide
                        $string17_chunk_Proxy_offensive_tool_keyword = /socket\s\=\snew\sSystem\.Net\.Sockets\.Socket\(System\.Net\.Sockets\.AddressFamily\.InterNetwork\,\sSystem\.Net\.Sockets\.SocketType\.Stream\,\sSystem\.Net\.Sockets\.ProtocolType\.Tcp\)/ nocase ascii wide

    condition:
        any of them
}