rule rule_Discord_RAT_2_0_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Discord-RAT-2.0' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Discord-RAT-2.0"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Discord_RAT_2_0_offensive_tool_keyword = /\/Discord\srat\.exe/ nocase ascii wide
                        $string2_Discord_RAT_2_0_offensive_tool_keyword = /\/Discord\-RAT\-2\.0/ nocase ascii wide
                        $string3_Discord_RAT_2_0_offensive_tool_keyword = /\/Discord\-RAT\-2\.0\.git/ nocase ascii wide
                        $string4_Discord_RAT_2_0_offensive_tool_keyword = /\/InstallStager\.exe/ nocase ascii wide
                        $string5_Discord_RAT_2_0_offensive_tool_keyword = /\/PasswordStealer\.dll/ nocase ascii wide
                        $string6_Discord_RAT_2_0_offensive_tool_keyword = /\/Resources\/Webcam\.dll/ nocase ascii wide
                        $string7_Discord_RAT_2_0_offensive_tool_keyword = /\/rootkit\.dll/ nocase ascii wide
                        $string8_Discord_RAT_2_0_offensive_tool_keyword = /\/run\s\/tn\s\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup\s\/I/ nocase ascii wide
                        $string9_Discord_RAT_2_0_offensive_tool_keyword = /\/Token\%20grabber\.dll/ nocase ascii wide
                        $string10_Discord_RAT_2_0_offensive_tool_keyword = /\/unrootkit\.dll/ nocase ascii wide
                        $string11_Discord_RAT_2_0_offensive_tool_keyword = /\\Discord\srat\.exe/ nocase ascii wide
                        $string12_Discord_RAT_2_0_offensive_tool_keyword = /\\Discord\-RAT\-2\.0/ nocase ascii wide
                        $string13_Discord_RAT_2_0_offensive_tool_keyword = /\\Discord\-RAT\-2\.0\-main/ nocase ascii wide
                        $string14_Discord_RAT_2_0_offensive_tool_keyword = /\\InstallStager\.exe/ nocase ascii wide
                        $string15_Discord_RAT_2_0_offensive_tool_keyword = /\\InstallStager\.pdb/ nocase ascii wide
                        $string16_Discord_RAT_2_0_offensive_tool_keyword = /\\PasswordStealer\.dll/ nocase ascii wide
                        $string17_Discord_RAT_2_0_offensive_tool_keyword = /\\rootkit\.dll/ nocase ascii wide
                        $string18_Discord_RAT_2_0_offensive_tool_keyword = /\\Token\sgrabber\.dll/ nocase ascii wide
                        $string19_Discord_RAT_2_0_offensive_tool_keyword = /\\unrootkit\.dll/ nocase ascii wide
                        $string20_Discord_RAT_2_0_offensive_tool_keyword = "10804539a495e0fcc79a6c2ab03e34d4b5c2bce1e134060839ff9b58dcfc1cf7" nocase ascii wide
                        $string21_Discord_RAT_2_0_offensive_tool_keyword = "121e18a8ad050f1a9510c6c32c0f4bb9adac3436170e2d1966788da4dc14c751" nocase ascii wide
                        $string22_Discord_RAT_2_0_offensive_tool_keyword = "4350a69f2630214a7b079e41e3ac2d7c5759a622a0cd1227ba12eee06d758d9a" nocase ascii wide
                        $string23_Discord_RAT_2_0_offensive_tool_keyword = "8fdae5b4490183c9057a684f0ac2f82dd5c8911cb2f43a54ff47a9ad6e93952a" nocase ascii wide
                        $string24_Discord_RAT_2_0_offensive_tool_keyword = "a3ca8d72edaf4ffb84a38e88a31f9e537d7d7b76f7cc7966583c7b4b4a811c74" nocase ascii wide
                        $string25_Discord_RAT_2_0_offensive_tool_keyword = "Advfirewall set allprofiles state off" nocase ascii wide
                        $string26_Discord_RAT_2_0_offensive_tool_keyword = "ae8abf10e555cee9769abea0e2d3379b11bc6a817f75a0b6038d294fa3d6a136" nocase ascii wide
                        $string27_Discord_RAT_2_0_offensive_tool_keyword = "c13a0cd7c2c2fd577703bff026b72ed81b51266afa047328c8ff1c4a4d965c97" nocase ascii wide
                        $string28_Discord_RAT_2_0_offensive_tool_keyword = "CC12258F-AF24-4773-A8E3-45D365BCBDE9" nocase ascii wide
                        $string29_Discord_RAT_2_0_offensive_tool_keyword = "cd075baa8305d9767316d5a2cc0ee60daf1f194a3c4b0d3386d1f8bd80f44907" nocase ascii wide
                        $string30_Discord_RAT_2_0_offensive_tool_keyword = "DBAE6A6E-AE23-4DE9-9AB2-6A8D2CD59DEF" nocase ascii wide
                        $string31_Discord_RAT_2_0_offensive_tool_keyword = "de314bd66c919dbd7b5e6614583f44a6461a1663f880873bc6746eed3a149457" nocase ascii wide
                        $string32_Discord_RAT_2_0_offensive_tool_keyword = "df78d4f9127039231844797c38428df24a80bd49eb11a5ee9a4dcf43f31573a9" nocase ascii wide
                        $string33_Discord_RAT_2_0_offensive_tool_keyword = /Discord\-RAT\-2\.0\-discordrat\.zip/ nocase ascii wide
                        $string34_Discord_RAT_2_0_offensive_tool_keyword = /Discord\-RAT\-2\.0\-master\.zip/ nocase ascii wide
                        $string35_Discord_RAT_2_0_offensive_tool_keyword = "Discord-RAT-by-Biscuit-main" nocase ascii wide
                        $string36_Discord_RAT_2_0_offensive_tool_keyword = "E776B801-614D-4E3C-A446-5A35B0CF3D08" nocase ascii wide
                        $string37_Discord_RAT_2_0_offensive_tool_keyword = "FAA8C7E2-4409-44F5-B2CA-EBBA4D4F41F0" nocase ascii wide
                        $string38_Discord_RAT_2_0_offensive_tool_keyword = /httpClient\.PostAsync\(\\"https\:\/\/file\.io\// nocase ascii wide
                        $string39_Discord_RAT_2_0_offensive_tool_keyword = /moom825\/Discord\-RAT\-2\.0/ nocase ascii wide
                        $string40_Discord_RAT_2_0_offensive_tool_keyword = "namespace Discord_rat" nocase ascii wide
                        $string41_Discord_RAT_2_0_offensive_tool_keyword = /SOFTWARE\\\$77config\\/ nocase ascii wide

    condition:
        any of them
}