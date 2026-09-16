rule rule_tunnelto_dev_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tunnelto.dev' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnelto.dev"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tunnelto_dev_greyware_tool_keyword = " install tunnelto" nocase ascii wide
                        $string2_tunnelto_dev_greyware_tool_keyword = "\"User-Agent\", \"tunnelto-client\"" nocase ascii wide
                        $string3_tunnelto_dev_greyware_tool_keyword = /\.\.\/tunnelto_lib/
                        $string4_tunnelto_dev_greyware_tool_keyword = /\.tunnelto\.dev/ nocase ascii wide
                        $string5_tunnelto_dev_greyware_tool_keyword = /\/tunnelto\.git/ nocase ascii wide
                        $string6_tunnelto_dev_greyware_tool_keyword = "/tunnelto/releases/latest" nocase ascii wide
                        $string7_tunnelto_dev_greyware_tool_keyword = "/tunnelto_server" nocase ascii wide
                        $string8_tunnelto_dev_greyware_tool_keyword = "/tunnelto_server/" nocase ascii wide
                        $string9_tunnelto_dev_greyware_tool_keyword = "/tunnelto_server:"
                        $string10_tunnelto_dev_greyware_tool_keyword = /\@tunnelto\.dev/ nocase ascii wide
                        $string11_tunnelto_dev_greyware_tool_keyword = /\\\.tunnelto\\key\.token/ nocase ascii wide
                        $string12_tunnelto_dev_greyware_tool_keyword = "84a0a90cde73607684db0142f2d9cd8e636f089514eba57835ec10806d8f5f4b" nocase ascii wide
                        $string13_tunnelto_dev_greyware_tool_keyword = "99736bcb172f9cbed127f25a80a6b91fe355c4673461878962d7b5ac94782db1" nocase ascii wide
                        $string14_tunnelto_dev_greyware_tool_keyword = "agrinman/tap/tunnelto" nocase ascii wide
                        $string15_tunnelto_dev_greyware_tool_keyword = "agrinman/tunnelto" nocase ascii wide
                        $string16_tunnelto_dev_greyware_tool_keyword = "--bin tunnelto" nocase ascii wide
                        $string17_tunnelto_dev_greyware_tool_keyword = "--bin tunnelto_server" nocase ascii wide
                        $string18_tunnelto_dev_greyware_tool_keyword = "--bin=tunnelto" nocase ascii wide
                        $string19_tunnelto_dev_greyware_tool_keyword = "--bin=tunnelto_server" nocase ascii wide
                        $string20_tunnelto_dev_greyware_tool_keyword = "cb70ca2937afdb647a8716f0b0d122f71f91dd7ce777250d0d2573f0ec47c5fc" nocase ascii wide
                        $string21_tunnelto_dev_greyware_tool_keyword = "f6e06ec835c02ff1f08cc12c77b067bce8eddd96b9015cefef250353c89e1fbd" nocase ascii wide
                        $string22_tunnelto_dev_greyware_tool_keyword = /ghcr\.io\/agrinman\/tunnelto/ nocase ascii wide
                        $string23_tunnelto_dev_greyware_tool_keyword = "tunnelto inspector" nocase ascii wide
                        $string24_tunnelto_dev_greyware_tool_keyword = "tunnelto --port "
                        $string25_tunnelto_dev_greyware_tool_keyword = "tunnelto_server/src/" nocase ascii wide
                        $string26_tunnelto_dev_greyware_tool_keyword = /tunnelto\-linux\.tar\.gz/
                        $string27_tunnelto_dev_greyware_tool_keyword = /tunnelto\-windows\.exe/ nocase ascii wide
                        $string28_tunnelto_dev_greyware_tool_keyword = /wormhole\.tunnelto\.dev/ nocase ascii wide

    condition:
        any of them
}