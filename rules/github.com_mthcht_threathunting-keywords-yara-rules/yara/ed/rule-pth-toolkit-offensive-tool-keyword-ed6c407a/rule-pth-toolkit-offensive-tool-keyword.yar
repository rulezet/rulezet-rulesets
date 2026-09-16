rule rule_pth_toolkit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pth-toolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pth-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pth_toolkit_offensive_tool_keyword = /\/pth\-toolkit\.git/ nocase ascii wide
                        $string2_pth_toolkit_offensive_tool_keyword = /\\pth\-toolkit\-master\\/ nocase ascii wide
                        $string3_pth_toolkit_offensive_tool_keyword = "127f1bfca312fa054a6e761df8c330967ed93dbe80ca78357e9b727faea0c5ef" nocase ascii wide
                        $string4_pth_toolkit_offensive_tool_keyword = "21f59168d9679a4567facac1b9146c930bc5e47c7c5ad248ed9e4e4582c25008" nocase ascii wide
                        $string5_pth_toolkit_offensive_tool_keyword = "26048dbf252141d3db4df311c6d70188c91bf1e4d3bb8cd8870b373566562a1d" nocase ascii wide
                        $string6_pth_toolkit_offensive_tool_keyword = "2e70b4bcc21c4aba64c283af815b20d52c79c93f14f9df623a6e588491155acf" nocase ascii wide
                        $string7_pth_toolkit_offensive_tool_keyword = "5ba6551843aaa623f0acd46941837e7dfde53ebbb648187a7f92efd211909d4f" nocase ascii wide
                        $string8_pth_toolkit_offensive_tool_keyword = "645524305b8203fddf667329025f7ce531c9bc664f3186d5db5cfa0ff55d53b5" nocase ascii wide
                        $string9_pth_toolkit_offensive_tool_keyword = "7bb549f48f1f33ad7f2494b078459ddd2a70c39ccc34a6edf3c0b9cd5efc9031" nocase ascii wide
                        $string10_pth_toolkit_offensive_tool_keyword = "9d3ebfe38c45da2bedc4250b4a5b8dcfe4a6c3505ccfe9a429f39b06a8ecc228" nocase ascii wide
                        $string11_pth_toolkit_offensive_tool_keyword = "b54792e5bf55da77fb025772858aee457ee4f679a8363faf35d0397db897b92a" nocase ascii wide
                        $string12_pth_toolkit_offensive_tool_keyword = "bb816067581c9cd64ea54ff05611c02efa4303ef95c86e027ca26aa2ae80c185" nocase ascii wide
                        $string13_pth_toolkit_offensive_tool_keyword = "bca5760a0654e457801cbc90c173703da7b359376a5c8855d1e7bd451a0e421b" nocase ascii wide
                        $string14_pth_toolkit_offensive_tool_keyword = "bf5a2aafdd2a8719cc733808bdb7009e6a7d4e6b889faa8a52e95b5ecc5d2337" nocase ascii wide
                        $string15_pth_toolkit_offensive_tool_keyword = "byt3bl33d3r/pth-toolkit" nocase ascii wide
                        $string16_pth_toolkit_offensive_tool_keyword = "db7c868e3042fbf2138bf10e7dae3fb72f38a269a6337e87669829a416aa3109" nocase ascii wide
                        $string17_pth_toolkit_offensive_tool_keyword = "e696484e41d70abaa95a09f2c77e5198a6556f5f5884f0d84bf21c5926c5afc7" nocase ascii wide
                        $string18_pth_toolkit_offensive_tool_keyword = "pth-rpcclient" nocase ascii wide
                        $string19_pth_toolkit_offensive_tool_keyword = "pth-smbclient" nocase ascii wide
                        $string20_pth_toolkit_offensive_tool_keyword = "pth-smbget" nocase ascii wide
                        $string21_pth_toolkit_offensive_tool_keyword = "pth-toolkit" nocase ascii wide
                        $string22_pth_toolkit_offensive_tool_keyword = /pth\-toolkit\-master\.zip/ nocase ascii wide
                        $string23_pth_toolkit_offensive_tool_keyword = "pth-winexe" nocase ascii wide
                        $string24_pth_toolkit_offensive_tool_keyword = "pth-wmic" nocase ascii wide
                        $string25_pth_toolkit_offensive_tool_keyword = "pth-wmis" nocase ascii wide

    condition:
        any of them
}