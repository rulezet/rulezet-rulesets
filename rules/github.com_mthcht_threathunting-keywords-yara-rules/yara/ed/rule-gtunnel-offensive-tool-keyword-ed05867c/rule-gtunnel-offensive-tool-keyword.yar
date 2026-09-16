rule rule_gTunnel_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gTunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gTunnel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gTunnel_offensive_tool_keyword = " gclient-build-image:latest " nocase ascii wide
                        $string2_gTunnel_offensive_tool_keyword = " gserver/Dockerfile " nocase ascii wide
                        $string3_gTunnel_offensive_tool_keyword = " gtunnel-server-debug" nocase ascii wide
                        $string4_gTunnel_offensive_tool_keyword = " --name gtunnel-server " nocase ascii wide
                        $string5_gTunnel_offensive_tool_keyword = "\"GTUNNEL_HOST\"" nocase ascii wide
                        $string6_gTunnel_offensive_tool_keyword = "\"GTUNNEL_PORT\"" nocase ascii wide
                        $string7_gTunnel_offensive_tool_keyword = /\/\.gtunnel\.conf/
                        $string8_gTunnel_offensive_tool_keyword = /\/gTunnel\.git/ nocase ascii wide
                        $string9_gTunnel_offensive_tool_keyword = "/gTunnel/gtuncli" nocase ascii wide
                        $string10_gTunnel_offensive_tool_keyword = "/gtunnel/releases/" nocase ascii wide
                        $string11_gTunnel_offensive_tool_keyword = "/gtunnel/tarball/" nocase ascii wide
                        $string12_gTunnel_offensive_tool_keyword = "/gtunnel/zipball/" nocase ascii wide
                        $string13_gTunnel_offensive_tool_keyword = /\/gtunnel_.{0,1000}\.log/
                        $string14_gTunnel_offensive_tool_keyword = "/src/gTunnel/configured" nocase ascii wide
                        $string15_gTunnel_offensive_tool_keyword = "/src/gTunnel/gserver/" nocase ascii wide
                        $string16_gTunnel_offensive_tool_keyword = "/src/gTunnel/logs"
                        $string17_gTunnel_offensive_tool_keyword = /\[\!\]\sFailed\sto\s\sbuild\sgtunnel\sserver\s/ nocase ascii wide
                        $string18_gTunnel_offensive_tool_keyword = /\[\!\]\sFailed\sto\screate\sgtunnel\-server\s/ nocase ascii wide
                        $string19_gTunnel_offensive_tool_keyword = /\[\!\]\sgClient\swith\suuid\:\s/ nocase ascii wide
                        $string20_gTunnel_offensive_tool_keyword = /\[\!\]\sStarting\sgServer\s/ nocase ascii wide
                        $string21_gTunnel_offensive_tool_keyword = /\]\sDefaulting\sport\sto\s1337/ nocase ascii wide
                        $string22_gTunnel_offensive_tool_keyword = /\]\sStarting\sadmin\sgrpc\sserver\son\sport\:\s/ nocase ascii wide
                        $string23_gTunnel_offensive_tool_keyword = /\]\sStarting\sclient\sgrpc\sserver\son\sport\:\s/ nocase ascii wide
                        $string24_gTunnel_offensive_tool_keyword = "36e3d1cc09aff85da9b79e384efe1b8e1db705fa061ff85db3c1ff14e979862e" nocase ascii wide
                        $string25_gTunnel_offensive_tool_keyword = "58b002643e9749100cc28705f590acc31b8e1ea19f542aead17c109f1f938f32" nocase ascii wide
                        $string26_gTunnel_offensive_tool_keyword = "74b8858250ad0401708fc5f45650d57ce5fef0a6ab9d190ad384997e3bb794fd" nocase ascii wide
                        $string27_gTunnel_offensive_tool_keyword = "7f093d1243dd87e82bbaf8ef261269466ca01a142b6a52c6fa145a8ec4ba3e3d" nocase ascii wide
                        $string28_gTunnel_offensive_tool_keyword = "9738590e365bc9b2c9baecbdbda391f294e1b991fe3744ac4b8c2107bf730565" nocase ascii wide
                        $string29_gTunnel_offensive_tool_keyword = "bdd26fca11a49c13b6f5a4549264172af36894eed9c2ef87ede374da202328ec" nocase ascii wide
                        $string30_gTunnel_offensive_tool_keyword = "c4ef00f9cf5b19babc7d9d7de5d4724c3b077be8dcd449b17dde8fe5297f5a98" nocase ascii wide
                        $string31_gTunnel_offensive_tool_keyword = "c6d0fdd776065e3d211426e2f7cfd0f69e17af3e0c7479777b8a65e87517f54c" nocase ascii wide
                        $string32_gTunnel_offensive_tool_keyword = "cfed546b7f1d9d3e030bbb3f412c93b77672da5f5b6a513c7bd54328ca483387" nocase ascii wide
                        $string33_gTunnel_offensive_tool_keyword = "e91f8a229b999a3a09389cddbdc7288de7b1905f8b69dc48a59e8249938eb82f" nocase ascii wide
                        $string34_gTunnel_offensive_tool_keyword = "Failed to receive initial tun stream message:" nocase ascii wide
                        $string35_gTunnel_offensive_tool_keyword = /gserver\/gServer\.go/ nocase ascii wide
                        $string36_gTunnel_offensive_tool_keyword = /gtunnel_\%s\.log/ nocase ascii wide
                        $string37_gTunnel_offensive_tool_keyword = /hotnops\.gitbook\.io\/gtunnel/ nocase ascii wide
                        $string38_gTunnel_offensive_tool_keyword = "hotnops/gTunnel" nocase ascii wide
                        $string39_gTunnel_offensive_tool_keyword = /s\.gServer\.connectedClients/ nocase ascii wide
                        $string40_gTunnel_offensive_tool_keyword = "Starting socks proxy on : " nocase ascii wide

    condition:
        any of them
}