rule rule_PowerLess_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerLess' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerLess"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerLess_offensive_tool_keyword = /\/Powerless\.dll/ nocase ascii wide
                        $string2_PowerLess_offensive_tool_keyword = /\\Powerless\.cpp/ nocase ascii wide
                        $string3_PowerLess_offensive_tool_keyword = /\\Powerless\.dll/ nocase ascii wide
                        $string4_PowerLess_offensive_tool_keyword = /\\Powerless\.exe/ nocase ascii wide
                        $string5_PowerLess_offensive_tool_keyword = /\\PowerLessCLR\.pdb/ nocase ascii wide
                        $string6_PowerLess_offensive_tool_keyword = "026db4159e7e36e00fdcef1e29f73b40030a3572" nocase ascii wide
                        $string7_PowerLess_offensive_tool_keyword = "0492b9ad7ae35ee1e0b6f53a6b7c2c75e9b5d427" nocase ascii wide
                        $string8_PowerLess_offensive_tool_keyword = "32224892b670467e23874d7e8abd2ef92987a7e6" nocase ascii wide
                        $string9_PowerLess_offensive_tool_keyword = "3a6431169073d61748829c31a9da29123dd61da8" nocase ascii wide
                        $string10_PowerLess_offensive_tool_keyword = "3bfec62c094366844c3e4c0e257e01678f55ef5b" nocase ascii wide
                        $string11_PowerLess_offensive_tool_keyword = "3fcec932530557ea3d1f38f06f477db4b0be5acb" nocase ascii wide
                        $string12_PowerLess_offensive_tool_keyword = "416291332a70407df5ff5d79072f5ad68cd802b9" nocase ascii wide
                        $string13_PowerLess_offensive_tool_keyword = "4810c782a8fe964512f08db91e8107e9af29edab" nocase ascii wide
                        $string14_PowerLess_offensive_tool_keyword = "679703e9859c20ab39d6be992aa7d979710d9ace" nocase ascii wide
                        $string15_PowerLess_offensive_tool_keyword = "92ae97557e18ca810999fc05c18e3c6c75476444" nocase ascii wide
                        $string16_PowerLess_offensive_tool_keyword = "97c0e103700b9f2464000cb63e10b68a4305dd33" nocase ascii wide
                        $string17_PowerLess_offensive_tool_keyword = "dcf01d7641ec3fec213ab8335625a3554b943ac8" nocase ascii wide
                        $string18_PowerLess_offensive_tool_keyword = "dd94382acb55e694ee38e1be7f5c0902be0e0d89" nocase ascii wide
                        $string19_PowerLess_offensive_tool_keyword = "eeebce1a4c3e05e21689acef000a5fcf0f17abc3" nocase ascii wide

    condition:
        any of them
}