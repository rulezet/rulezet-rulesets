rule tunnelto_dev
{
    meta:
        description = "Detection patterns for the tool 'tunnelto.dev' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnelto.dev"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " install tunnelto" nocase ascii wide
                        $string2 = "\"User-Agent\", \"tunnelto-client\"" nocase ascii wide
                        $string3 = /\.\.\/tunnelto_lib/
                        $string4 = /\.tunnelto\.dev/ nocase ascii wide
                        $string5 = /\/tunnelto\.git/ nocase ascii wide
                        $string6 = "/tunnelto/releases/latest" nocase ascii wide
                        $string7 = "/tunnelto_server" nocase ascii wide
                        $string8 = "/tunnelto_server/" nocase ascii wide
                        $string9 = "/tunnelto_server:"
                        $string10 = /\@tunnelto\.dev/ nocase ascii wide
                        $string11 = /\\\.tunnelto\\key\.token/ nocase ascii wide
                        $string12 = "84a0a90cde73607684db0142f2d9cd8e636f089514eba57835ec10806d8f5f4b" nocase ascii wide
                        $string13 = "99736bcb172f9cbed127f25a80a6b91fe355c4673461878962d7b5ac94782db1" nocase ascii wide
                        $string14 = "agrinman/tap/tunnelto" nocase ascii wide
                        $string15 = "agrinman/tunnelto" nocase ascii wide
                        $string16 = "--bin tunnelto" nocase ascii wide
                        $string17 = "--bin tunnelto_server" nocase ascii wide
                        $string18 = "--bin=tunnelto" nocase ascii wide
                        $string19 = "--bin=tunnelto_server" nocase ascii wide
                        $string20 = "cb70ca2937afdb647a8716f0b0d122f71f91dd7ce777250d0d2573f0ec47c5fc" nocase ascii wide
                        $string21 = "f6e06ec835c02ff1f08cc12c77b067bce8eddd96b9015cefef250353c89e1fbd" nocase ascii wide
                        $string22 = /ghcr\.io\/agrinman\/tunnelto/ nocase ascii wide
                        $string23 = "tunnelto inspector" nocase ascii wide
                        $string24 = "tunnelto --port "
                        $string25 = "tunnelto_server/src/" nocase ascii wide
                        $string26 = /tunnelto\-linux\.tar\.gz/
                        $string27 = /tunnelto\-windows\.exe/ nocase ascii wide
                        $string28 = /wormhole\.tunnelto\.dev/ nocase ascii wide

    condition:
        any of them
}