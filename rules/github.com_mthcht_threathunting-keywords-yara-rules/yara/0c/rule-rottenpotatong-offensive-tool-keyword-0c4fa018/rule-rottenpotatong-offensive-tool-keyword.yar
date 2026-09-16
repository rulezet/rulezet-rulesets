rule rule_RottenPotatoNG_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RottenPotatoNG' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RottenPotatoNG"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RottenPotatoNG_offensive_tool_keyword = " CMSFRottenPotato::" nocase ascii wide
                        $string2_RottenPotatoNG_offensive_tool_keyword = /\/RottenPotatoNG\.git/ nocase ascii wide
                        $string3_RottenPotatoNG_offensive_tool_keyword = /\\MSFRottenPotato\.cpp/ nocase ascii wide
                        $string4_RottenPotatoNG_offensive_tool_keyword = /\\MSFRottenPotato\.log/ nocase ascii wide
                        $string5_RottenPotatoNG_offensive_tool_keyword = /\\MSFRottenPotato\.sln/ nocase ascii wide
                        $string6_RottenPotatoNG_offensive_tool_keyword = /\\MSFRottenPotatoTestHarness\./ nocase ascii wide
                        $string7_RottenPotatoNG_offensive_tool_keyword = /\\RottenPotatoNG\-main/ nocase ascii wide
                        $string8_RottenPotatoNG_offensive_tool_keyword = /\\RottenPotatoNG\-master/ nocase ascii wide
                        $string9_RottenPotatoNG_offensive_tool_keyword = "0fb342f94f359c9f54205a979854b7a3a3910bb7e118f0fc44cead28ebd81f0d" nocase ascii wide
                        $string10_RottenPotatoNG_offensive_tool_keyword = "1d6d4c0b001fc20d404d6e2ec3625d9fc245c31484023e2ac7a3b123eec8cce1" nocase ascii wide
                        $string11_RottenPotatoNG_offensive_tool_keyword = "2e67c9adb1962e9b5c9a025b2901fc01e2a214b53f5552656a07f2057307f6e5" nocase ascii wide
                        $string12_RottenPotatoNG_offensive_tool_keyword = "3a0b118ddd6b02426aba9ead93a576f7b99997cf6f07907147dd0d3294ff8887" nocase ascii wide
                        $string13_RottenPotatoNG_offensive_tool_keyword = "4164003E-BA47-4A95-8586-D5AAC399C050" nocase ascii wide
                        $string14_RottenPotatoNG_offensive_tool_keyword = "44ae8a2088ca416ed3c802f50eb55adbbb2d01fd528e76be8dd449004ce470ad" nocase ascii wide
                        $string15_RottenPotatoNG_offensive_tool_keyword = "4a9d528dc102560378cff97262caeae12e24e64b94e381e6e5709e3b2bb89291" nocase ascii wide
                        $string16_RottenPotatoNG_offensive_tool_keyword = "4d1fd422503b03f89fba5fa6d51e5bccb3e6cd3254461de316ca25296da38d4b" nocase ascii wide
                        $string17_RottenPotatoNG_offensive_tool_keyword = "5952e312083c8121c4856b566421aa23afe427e7f1eb0b4e6ae34515b906705a" nocase ascii wide
                        $string18_RottenPotatoNG_offensive_tool_keyword = "62971b70cd61bff1243ad58121912ea8aa7ee1cfb553b2310cbbd4c32529e151" nocase ascii wide
                        $string19_RottenPotatoNG_offensive_tool_keyword = "73141d2560cc8922220ff44a83d36aa79e759ae349dea6300cf6c4adde81982d" nocase ascii wide
                        $string20_RottenPotatoNG_offensive_tool_keyword = "7E1BCC8E-F61C-4728-BB8A-28FB42928256" nocase ascii wide
                        $string21_RottenPotatoNG_offensive_tool_keyword = "889dc7cce75cae74fe761345fc1f0e02e8b97f705c92a5a136666250301a1215" nocase ascii wide
                        $string22_RottenPotatoNG_offensive_tool_keyword = "889dc7cce75cae74fe761345fc1f0e02e8b97f705c92a5a136666250301a1215" nocase ascii wide
                        $string23_RottenPotatoNG_offensive_tool_keyword = "8aed04233ee4b33500c6af6da612bed71770628910a761c325987d24737c5c28" nocase ascii wide
                        $string24_RottenPotatoNG_offensive_tool_keyword = "9302e09f9f1856391bc218c2b7cdd898e8934f18efc31dd9b27f52b0e2d1812c" nocase ascii wide
                        $string25_RottenPotatoNG_offensive_tool_keyword = "9d584d6906a84285108c0500cab449e016a42bfd2b365f19ae851ff5312e2a33" nocase ascii wide
                        $string26_RottenPotatoNG_offensive_tool_keyword = "be038bcb58b9e744c9821823ac59c3d9f4cc9456f445c41a840b7a6acbc21fc3" nocase ascii wide
                        $string27_RottenPotatoNG_offensive_tool_keyword = "breenmachine/RottenPotatoNG" nocase ascii wide
                        $string28_RottenPotatoNG_offensive_tool_keyword = "e30560b23a52a32b2ad8250466c1b0a975348ab4f6240e629288bc4ad74430fb" nocase ascii wide
                        $string29_RottenPotatoNG_offensive_tool_keyword = "e30560b23a52a32b2ad8250466c1b0a975348ab4f6240e629288bc4ad74430fb" nocase ascii wide
                        $string30_RottenPotatoNG_offensive_tool_keyword = /MSFRottenPotato\.dll/ nocase ascii wide
                        $string31_RottenPotatoNG_offensive_tool_keyword = /MSFRottenPotato\.exe/ nocase ascii wide
                        $string32_RottenPotatoNG_offensive_tool_keyword = /MSFRottenPotatoTestHarness\.exe/ nocase ascii wide

    condition:
        any of them
}