rule rule_linikatz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'linikatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linikatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_linikatz_offensive_tool_keyword = /\/linikatz\.git/
                        $string2_linikatz_offensive_tool_keyword = "/vas/fuzzers/fuzz/"
                        $string3_linikatz_offensive_tool_keyword = "12e9256bbb969343cc20fa9e259c0af1bf12d6c7bd0263bd7b2a60575b73cf62"
                        $string4_linikatz_offensive_tool_keyword = "4681186a8bcaff98f0d2513d30add67345491b95f7f743883e6ca2506ba7aaaf"
                        $string5_linikatz_offensive_tool_keyword = "612789c90ec1040d821a985265ea3b2f57e2c8df90b3880752dcb869e45256bc"
                        $string6_linikatz_offensive_tool_keyword = "66c368f799227a9b571f841057e2d5f12c862360d5f7f564da9936acd67c66a0"
                        $string7_linikatz_offensive_tool_keyword = "691f577714a4ae22bc22ec49edec5a15bf546a9827e8e1cf4e9e688b2ba9f72e"
                        $string8_linikatz_offensive_tool_keyword = "8672d46e879f704b4b41a401c1a0aae5e6365f18a798a1fbaa4b1a8e711db34b"
                        $string9_linikatz_offensive_tool_keyword = "9a3a44c544cd596ebf94583614035575e746f57315e20ec56a819c7152ba3fe9"
                        $string10_linikatz_offensive_tool_keyword = "a0101bdeeb3f99c0640c203716381ef9f6bad8e89973eaa608c801ed3f6ccace"
                        $string11_linikatz_offensive_tool_keyword = "a1b3d36a9cc4bc118c646ae5430a6e0fc811f2ec3614a3de9682b5c07eaade2d"
                        $string12_linikatz_offensive_tool_keyword = "adf6d464ce449914110607706da329993186f52f99074af1b7b1734a46dd4fcf"
                        $string13_linikatz_offensive_tool_keyword = "b2363d2b238f9336bb270fe96db258243668a916d7ddf94bf3a3126ed7cae508"
                        $string14_linikatz_offensive_tool_keyword = "b8ad30b89d6cabe30501ed963b21dcaec70b3283608682678629feae2c1b2235"
                        $string15_linikatz_offensive_tool_keyword = "C34208EA-8C33-473D-A9B4-53FB40347EA0"
                        $string16_linikatz_offensive_tool_keyword = "cbeecb2981c75b8f066b1f04f19f2095bdcf22f19d0d3f1099b83963547c00cb"
                        $string17_linikatz_offensive_tool_keyword = "CiscoCXSecurity/linikatz"
                        $string18_linikatz_offensive_tool_keyword = /config_steal\s\/etc\/krb5\.conf\s\/etc\/krb5\.keytab/
                        $string19_linikatz_offensive_tool_keyword = "e69a6f8e45f8dd8ee977b6aed73cac25537c39f6fb74cf9cc225f2af1d9e4cd7"
                        $string20_linikatz_offensive_tool_keyword = /ERPScan\-tockenchpoken\.zip/
                        $string21_linikatz_offensive_tool_keyword = "f1696fdc28bdb9e757a14b2ba9e698af8f70bb928d3c9e9fb524249f20231d08"
                        $string22_linikatz_offensive_tool_keyword = "f3aacbbaacceb0bdcac49d9b5e1da52d6883b7d736ca68f0a98f5a1d4838b995"
                        $string23_linikatz_offensive_tool_keyword = /fuzzers\/rippackets\.pl/
                        $string24_linikatz_offensive_tool_keyword = /linikatz\.sh/
                        $string25_linikatz_offensive_tool_keyword = /linikatz\.zip/
                        $string26_linikatz_offensive_tool_keyword = "P0rtcu11i5!"
                        $string27_linikatz_offensive_tool_keyword = /unix_cached_ad_hashes\.rb/
                        $string28_linikatz_offensive_tool_keyword = /unix_kerberos_tickets\.rb/

    condition:
        any of them
}