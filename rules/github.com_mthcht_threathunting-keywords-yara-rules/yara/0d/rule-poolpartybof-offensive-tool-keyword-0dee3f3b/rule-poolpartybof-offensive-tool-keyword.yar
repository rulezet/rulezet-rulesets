rule rule_PoolPartyBof_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PoolPartyBof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PoolPartyBof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PoolPartyBof_offensive_tool_keyword = /\shavoc_bof\.py/ nocase ascii wide
                        $string2_PoolPartyBof_offensive_tool_keyword = /\/havoc_bof\.py/ nocase ascii wide
                        $string3_PoolPartyBof_offensive_tool_keyword = /\/PoolPartyBof\.git/ nocase ascii wide
                        $string4_PoolPartyBof_offensive_tool_keyword = "/PoolPartyBof/releases/download/" nocase ascii wide
                        $string5_PoolPartyBof_offensive_tool_keyword = "/PoolPartyBof/tarball/" nocase ascii wide
                        $string6_PoolPartyBof_offensive_tool_keyword = "/PoolPartyBof/zipball/" nocase ascii wide
                        $string7_PoolPartyBof_offensive_tool_keyword = /\/tmp\/beacon_x64\.bin/
                        $string8_PoolPartyBof_offensive_tool_keyword = /\/tmp\/shellcode\.bin/
                        $string9_PoolPartyBof_offensive_tool_keyword = "0xEr3bus/PoolPartyBof" nocase ascii wide
                        $string10_PoolPartyBof_offensive_tool_keyword = "584ed22563bcc356a615c44d376bb194cea96dd028f15f58b5f412bbd26008e8" nocase ascii wide
                        $string11_PoolPartyBof_offensive_tool_keyword = "83d99bedd82a5ddf6a8965fbc47b48eb05afb773926f5b781dcbaea39aaae048" nocase ascii wide
                        $string12_PoolPartyBof_offensive_tool_keyword = "a59b7561dd5d4715889191c2940059098a322528379a1d66dd1a960ffa87a601" nocase ascii wide
                        $string13_PoolPartyBof_offensive_tool_keyword = "b0b6fc7655489a38277889cc4a101e8832b49b08e754110bdba599c6c4c9b6ed" nocase ascii wide
                        $string14_PoolPartyBof_offensive_tool_keyword = "b2b3853690de7ac7089834b95a6aaf107baa61d6f85d3c941abd67f2b8540020" nocase ascii wide
                        $string15_PoolPartyBof_offensive_tool_keyword = "bb7f042ac2b1d062178a3168cda13c75564282b4d9c5aa231ff2dd42fb343fd1" nocase ascii wide
                        $string16_PoolPartyBof_offensive_tool_keyword = "c9cb3638fbe1f4f28f08e4fad0394c4535de00e16854a2952936787d032c6c2f" nocase ascii wide
                        $string17_PoolPartyBof_offensive_tool_keyword = "cb10930997bcc3b5667fea0bf825208cfd87f96f6990082e81cd31123a8b01b7" nocase ascii wide
                        $string18_PoolPartyBof_offensive_tool_keyword = "d399157530a7b9d0678ab86e8dd1a24e018f38f68f614d06fa22e4b634e933e3" nocase ascii wide
                        $string19_PoolPartyBof_offensive_tool_keyword = "d5cd8e3db9434a439d26e9e870abfa4e4b45bb502e61878966ba3e90c0c1cfd3" nocase ascii wide
                        $string20_PoolPartyBof_offensive_tool_keyword = "daf6f6b42fced73af9fb5339935a02d8bedc96719d35a2bc5153d931e310df3b" nocase ascii wide
                        $string21_PoolPartyBof_offensive_tool_keyword = /PoolPartyBof\.cna/ nocase ascii wide
                        $string22_PoolPartyBof_offensive_tool_keyword = /PoolPartyBof\.h/ nocase ascii wide
                        $string23_PoolPartyBof_offensive_tool_keyword = /PoolPartyBof\.zip/ nocase ascii wide
                        $string24_PoolPartyBof_offensive_tool_keyword = /PoolPartyBof_V4\.x64/ nocase ascii wide
                        $string25_PoolPartyBof_offensive_tool_keyword = /PoolPartyBof_V4\.x64/ nocase ascii wide
                        $string26_PoolPartyBof_offensive_tool_keyword = /PoolPartyBof_V5\.x64/ nocase ascii wide
                        $string27_PoolPartyBof_offensive_tool_keyword = /PoolPartyBof_V6\.x64/ nocase ascii wide
                        $string28_PoolPartyBof_offensive_tool_keyword = /PoolPartyBof_V7\.x64/ nocase ascii wide
                        $string29_PoolPartyBof_offensive_tool_keyword = /PoolPartyBof_V8\.x64/ nocase ascii wide

    condition:
        any of them
}