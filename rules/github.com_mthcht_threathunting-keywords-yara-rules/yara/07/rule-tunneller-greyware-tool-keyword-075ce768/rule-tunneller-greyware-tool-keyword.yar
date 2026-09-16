rule rule_tunneller_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tunneller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunneller"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tunneller_greyware_tool_keyword = /\/tunneller\.git/ nocase ascii wide
                        $string2_tunneller_greyware_tool_keyword = "/tunneller/releases/" nocase ascii wide
                        $string3_tunneller_greyware_tool_keyword = "/tunneller-darwin-amd64"
                        $string4_tunneller_greyware_tool_keyword = "/tunneller-darwin-amd64"
                        $string5_tunneller_greyware_tool_keyword = "/tunneller-darwin-amd64"
                        $string6_tunneller_greyware_tool_keyword = "/tunneller-darwin-amd64"
                        $string7_tunneller_greyware_tool_keyword = "/tunneller-darwin-i386"
                        $string8_tunneller_greyware_tool_keyword = "/tunneller-darwin-i386"
                        $string9_tunneller_greyware_tool_keyword = "/tunneller-darwin-i386"
                        $string10_tunneller_greyware_tool_keyword = "/tunneller-darwin-i386"
                        $string11_tunneller_greyware_tool_keyword = "/tunneller-freebsd-amd64" nocase ascii wide
                        $string12_tunneller_greyware_tool_keyword = "/tunneller-freebsd-amd64" nocase ascii wide
                        $string13_tunneller_greyware_tool_keyword = "/tunneller-freebsd-amd64" nocase ascii wide
                        $string14_tunneller_greyware_tool_keyword = "/tunneller-freebsd-amd64" nocase ascii wide
                        $string15_tunneller_greyware_tool_keyword = "/tunneller-freebsd-i386" nocase ascii wide
                        $string16_tunneller_greyware_tool_keyword = "/tunneller-freebsd-i386" nocase ascii wide
                        $string17_tunneller_greyware_tool_keyword = "/tunneller-freebsd-i386" nocase ascii wide
                        $string18_tunneller_greyware_tool_keyword = "/tunneller-freebsd-i386" nocase ascii wide
                        $string19_tunneller_greyware_tool_keyword = "/tunneller-linux-amd64"
                        $string20_tunneller_greyware_tool_keyword = "/tunneller-linux-amd64"
                        $string21_tunneller_greyware_tool_keyword = "/tunneller-linux-amd64"
                        $string22_tunneller_greyware_tool_keyword = "/tunneller-linux-amd64"
                        $string23_tunneller_greyware_tool_keyword = "/tunneller-linux-i386"
                        $string24_tunneller_greyware_tool_keyword = "/tunneller-linux-i386"
                        $string25_tunneller_greyware_tool_keyword = "/tunneller-linux-i386"
                        $string26_tunneller_greyware_tool_keyword = "/tunneller-linux-i386"
                        $string27_tunneller_greyware_tool_keyword = "087dae4b718907c400d19d3e497619042ad74036da714be2812ab423e0a86e84" nocase ascii wide
                        $string28_tunneller_greyware_tool_keyword = "1556d7d7fe7f2342854a24b05c3eca7e593d7e22021c559118c3fde32950bfd0" nocase ascii wide
                        $string29_tunneller_greyware_tool_keyword = "23588b81078e4ce796050b5eb3f87e37be16233d45ca17e222be509445127a3f" nocase ascii wide
                        $string30_tunneller_greyware_tool_keyword = "2d5d5cd63277002d698485c5a87a51c1c8d520a963ae1c1689c9e6c5c4964c0c" nocase ascii wide
                        $string31_tunneller_greyware_tool_keyword = "4f91e07aba2c4e94121f45cfb8252d2e173d565a4a15faacd7b3fa3f78b0d978" nocase ascii wide
                        $string32_tunneller_greyware_tool_keyword = "51921c04f725490abfce3611cef91f602314bb272240d7d4a252bf16a2199154" nocase ascii wide
                        $string33_tunneller_greyware_tool_keyword = "5370c48e778806b0676a70e133a32a7ed674ad22545bb61e120198236504245a" nocase ascii wide
                        $string34_tunneller_greyware_tool_keyword = "582b8f96d51ff83c2daf3970faa3c141a18dc8b1af0b23a3dc40aee1d04c6702" nocase ascii wide
                        $string35_tunneller_greyware_tool_keyword = "6c23f9dc5552c6286c852faa91236587470efaf28af92c5b4742feac70ffed6b" nocase ascii wide
                        $string36_tunneller_greyware_tool_keyword = "6f072e5783a999399690a8fbb7aff14f818746a910165bb7514576bf9ef179da" nocase ascii wide
                        $string37_tunneller_greyware_tool_keyword = "70bac6ab24591aa3df6592daacec697e11fdf865e3f27b8ccb7fa5a65934d96d" nocase ascii wide
                        $string38_tunneller_greyware_tool_keyword = "86f182e121994ab7f27c9936c947bf21151dbaa1a2c94640c9b3493e3101c98a" nocase ascii wide
                        $string39_tunneller_greyware_tool_keyword = "8bbfc29e4494eaa861f1e8ceea0982279cae939a7cbe4a6606919e07a67b85bc" nocase ascii wide
                        $string40_tunneller_greyware_tool_keyword = "959dfbb8cd213bd33aa99fcf4494c61397dc39685f43806ddd9804798d4c94cb" nocase ascii wide
                        $string41_tunneller_greyware_tool_keyword = "9f6b80fa0ffaad84c92776eaa2af7a16d5fcb724ac12ed9a07dffd88565c6397" nocase ascii wide
                        $string42_tunneller_greyware_tool_keyword = "a17972b286ec9492e224a2adcc4ec7487615caec87a04be7d7a1c0bbfc0f0b43" nocase ascii wide
                        $string43_tunneller_greyware_tool_keyword = "a857a9f7a34b247348439a6b13dda18e4aafa381eb7d50215610d9d360d68485" nocase ascii wide
                        $string44_tunneller_greyware_tool_keyword = "aca3bacd0f7f2a5e75ed74643e1fbb57ec10dc94f675dab12f8d7aeb48c3a503" nocase ascii wide
                        $string45_tunneller_greyware_tool_keyword = "ae4e32d838b180b920722598fa8cc91533742f1bc53805520b372f1f210d6833" nocase ascii wide
                        $string46_tunneller_greyware_tool_keyword = "b56153a4717acef3981496c1b7612efb801ce9b90ec941f1ebf69026d7fbbe20" nocase ascii wide
                        $string47_tunneller_greyware_tool_keyword = "b99def34d979c04dd81857a6ba93e79d8a16bcefecc8f4607e3c1cee097f41c1" nocase ascii wide
                        $string48_tunneller_greyware_tool_keyword = "c3a41b08c2665cc4036b9540ee39aa4a0786ed2416f03fe2ae5429ef303f409e" nocase ascii wide
                        $string49_tunneller_greyware_tool_keyword = "ce9e92734048598d84c3ca3a1da32ecdf759e43b3e13716bf0bf91183c7544f2" nocase ascii wide
                        $string50_tunneller_greyware_tool_keyword = "d49e100ae7518571c6b4953693cc63e975072203787c492f389326ea3b1e988f" nocase ascii wide
                        $string51_tunneller_greyware_tool_keyword = "eefd30efe33687408541ad00fead452f4f341c32fad1a77e84006ae7aa4fbe9a" nocase ascii wide
                        $string52_tunneller_greyware_tool_keyword = "efa4485dbd9d5813411e35144b17f676459fb681dc67c5a84d61da68f77099f8" nocase ascii wide
                        $string53_tunneller_greyware_tool_keyword = "Launch the client, exposing a local service to the internet" nocase ascii wide
                        $string54_tunneller_greyware_tool_keyword = "skx/tunneller" nocase ascii wide
                        $string55_tunneller_greyware_tool_keyword = "You must specify the local host:port to expose" nocase ascii wide

    condition:
        any of them
}