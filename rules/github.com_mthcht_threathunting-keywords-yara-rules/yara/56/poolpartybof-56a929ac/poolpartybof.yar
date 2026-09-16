rule PoolPartyBof
{
    meta:
        description = "Detection patterns for the tool 'PoolPartyBof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PoolPartyBof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\shavoc_bof\.py/ nocase ascii wide
                        $string2 = /\/havoc_bof\.py/ nocase ascii wide
                        $string3 = /\/PoolPartyBof\.git/ nocase ascii wide
                        $string4 = "/PoolPartyBof/releases/download/" nocase ascii wide
                        $string5 = "/PoolPartyBof/tarball/" nocase ascii wide
                        $string6 = "/PoolPartyBof/zipball/" nocase ascii wide
                        $string7 = /\/tmp\/beacon_x64\.bin/
                        $string8 = /\/tmp\/shellcode\.bin/
                        $string9 = "0xEr3bus/PoolPartyBof" nocase ascii wide
                        $string10 = "584ed22563bcc356a615c44d376bb194cea96dd028f15f58b5f412bbd26008e8" nocase ascii wide
                        $string11 = "83d99bedd82a5ddf6a8965fbc47b48eb05afb773926f5b781dcbaea39aaae048" nocase ascii wide
                        $string12 = "a59b7561dd5d4715889191c2940059098a322528379a1d66dd1a960ffa87a601" nocase ascii wide
                        $string13 = "b0b6fc7655489a38277889cc4a101e8832b49b08e754110bdba599c6c4c9b6ed" nocase ascii wide
                        $string14 = "b2b3853690de7ac7089834b95a6aaf107baa61d6f85d3c941abd67f2b8540020" nocase ascii wide
                        $string15 = "bb7f042ac2b1d062178a3168cda13c75564282b4d9c5aa231ff2dd42fb343fd1" nocase ascii wide
                        $string16 = "c9cb3638fbe1f4f28f08e4fad0394c4535de00e16854a2952936787d032c6c2f" nocase ascii wide
                        $string17 = "cb10930997bcc3b5667fea0bf825208cfd87f96f6990082e81cd31123a8b01b7" nocase ascii wide
                        $string18 = "d399157530a7b9d0678ab86e8dd1a24e018f38f68f614d06fa22e4b634e933e3" nocase ascii wide
                        $string19 = "d5cd8e3db9434a439d26e9e870abfa4e4b45bb502e61878966ba3e90c0c1cfd3" nocase ascii wide
                        $string20 = "daf6f6b42fced73af9fb5339935a02d8bedc96719d35a2bc5153d931e310df3b" nocase ascii wide
                        $string21 = /PoolPartyBof\.cna/ nocase ascii wide
                        $string22 = /PoolPartyBof\.h/ nocase ascii wide
                        $string23 = /PoolPartyBof\.zip/ nocase ascii wide
                        $string24 = /PoolPartyBof_V4\.x64/ nocase ascii wide
                        $string25 = /PoolPartyBof_V4\.x64/ nocase ascii wide
                        $string26 = /PoolPartyBof_V5\.x64/ nocase ascii wide
                        $string27 = /PoolPartyBof_V6\.x64/ nocase ascii wide
                        $string28 = /PoolPartyBof_V7\.x64/ nocase ascii wide
                        $string29 = /PoolPartyBof_V8\.x64/ nocase ascii wide

    condition:
        any of them
}