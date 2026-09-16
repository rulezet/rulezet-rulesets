rule gTunnel
{
    meta:
        description = "Detection patterns for the tool 'gTunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gTunnel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " gclient-build-image:latest " nocase ascii wide
                        $string2 = " gserver/Dockerfile " nocase ascii wide
                        $string3 = " gtunnel-server-debug" nocase ascii wide
                        $string4 = " --name gtunnel-server " nocase ascii wide
                        $string5 = "\"GTUNNEL_HOST\"" nocase ascii wide
                        $string6 = "\"GTUNNEL_PORT\"" nocase ascii wide
                        $string7 = /\/\.gtunnel\.conf/
                        $string8 = /\/gTunnel\.git/ nocase ascii wide
                        $string9 = "/gTunnel/gtuncli" nocase ascii wide
                        $string10 = "/gtunnel/releases/" nocase ascii wide
                        $string11 = "/gtunnel/tarball/" nocase ascii wide
                        $string12 = "/gtunnel/zipball/" nocase ascii wide
                        $string13 = /\/gtunnel_.{0,1000}\.log/
                        $string14 = "/src/gTunnel/configured" nocase ascii wide
                        $string15 = "/src/gTunnel/gserver/" nocase ascii wide
                        $string16 = "/src/gTunnel/logs"
                        $string17 = /\[\!\]\sFailed\sto\s\sbuild\sgtunnel\sserver\s/ nocase ascii wide
                        $string18 = /\[\!\]\sFailed\sto\screate\sgtunnel\-server\s/ nocase ascii wide
                        $string19 = /\[\!\]\sgClient\swith\suuid\:\s/ nocase ascii wide
                        $string20 = /\[\!\]\sStarting\sgServer\s/ nocase ascii wide
                        $string21 = /\]\sDefaulting\sport\sto\s1337/ nocase ascii wide
                        $string22 = /\]\sStarting\sadmin\sgrpc\sserver\son\sport\:\s/ nocase ascii wide
                        $string23 = /\]\sStarting\sclient\sgrpc\sserver\son\sport\:\s/ nocase ascii wide
                        $string24 = "36e3d1cc09aff85da9b79e384efe1b8e1db705fa061ff85db3c1ff14e979862e" nocase ascii wide
                        $string25 = "58b002643e9749100cc28705f590acc31b8e1ea19f542aead17c109f1f938f32" nocase ascii wide
                        $string26 = "74b8858250ad0401708fc5f45650d57ce5fef0a6ab9d190ad384997e3bb794fd" nocase ascii wide
                        $string27 = "7f093d1243dd87e82bbaf8ef261269466ca01a142b6a52c6fa145a8ec4ba3e3d" nocase ascii wide
                        $string28 = "9738590e365bc9b2c9baecbdbda391f294e1b991fe3744ac4b8c2107bf730565" nocase ascii wide
                        $string29 = "bdd26fca11a49c13b6f5a4549264172af36894eed9c2ef87ede374da202328ec" nocase ascii wide
                        $string30 = "c4ef00f9cf5b19babc7d9d7de5d4724c3b077be8dcd449b17dde8fe5297f5a98" nocase ascii wide
                        $string31 = "c6d0fdd776065e3d211426e2f7cfd0f69e17af3e0c7479777b8a65e87517f54c" nocase ascii wide
                        $string32 = "cfed546b7f1d9d3e030bbb3f412c93b77672da5f5b6a513c7bd54328ca483387" nocase ascii wide
                        $string33 = "e91f8a229b999a3a09389cddbdc7288de7b1905f8b69dc48a59e8249938eb82f" nocase ascii wide
                        $string34 = "Failed to receive initial tun stream message:" nocase ascii wide
                        $string35 = /gserver\/gServer\.go/ nocase ascii wide
                        $string36 = /gtunnel_\%s\.log/ nocase ascii wide
                        $string37 = /hotnops\.gitbook\.io\/gtunnel/ nocase ascii wide
                        $string38 = "hotnops/gTunnel" nocase ascii wide
                        $string39 = /s\.gServer\.connectedClients/ nocase ascii wide
                        $string40 = "Starting socks proxy on : " nocase ascii wide

    condition:
        any of them
}