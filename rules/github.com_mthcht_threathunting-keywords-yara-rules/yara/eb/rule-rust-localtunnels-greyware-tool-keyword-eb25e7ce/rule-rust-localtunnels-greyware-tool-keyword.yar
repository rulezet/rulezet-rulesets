rule rule_Rust_Localtunnels_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Rust Localtunnels' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rust Localtunnels"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Rust_Localtunnels_greyware_tool_keyword = /\/etc\/systemd\/system\/localtunnel\.service/
                        $string2_Rust_Localtunnels_greyware_tool_keyword = /\/localtunnel\-linux\-.{0,1000}\.tar/
                        $string3_Rust_Localtunnels_greyware_tool_keyword = "027e4741b0ffea0c4a7b7d89fe584de5655ac140bc60994df35e0d19565f0817" nocase ascii wide
                        $string4_Rust_Localtunnels_greyware_tool_keyword = "083d05fd31ebe56b9a6808a1013858db66e784140ab82e0c9c410bb337a7a12d" nocase ascii wide
                        $string5_Rust_Localtunnels_greyware_tool_keyword = "415737ed99f26da6de88354af631091e63510fe1ad26cf6572878a27f160e10d" nocase ascii wide
                        $string6_Rust_Localtunnels_greyware_tool_keyword = "4688b505beadf010c8c571386ded7ff67a07fcbc261108b74b6d24b8372f609e" nocase ascii wide
                        $string7_Rust_Localtunnels_greyware_tool_keyword = "52be14d6204dd665dc3ccf2eb50179111a28cc0d8d473c7eef3b218f94e36b6d" nocase ascii wide
                        $string8_Rust_Localtunnels_greyware_tool_keyword = "643433c960c261ea697d35970cbeac38e8a66889cff754a613eeb790368e6f37" nocase ascii wide
                        $string9_Rust_Localtunnels_greyware_tool_keyword = "6571057d649cfccb2d84577c32a83ad5d4f5fac298e72f08a6974cf4a620c7ec" nocase ascii wide
                        $string10_Rust_Localtunnels_greyware_tool_keyword = "db5dd550a11b68ef48f084413db4cfe87f677cda58c7168f777abfcdc63d6479" nocase ascii wide
                        $string11_Rust_Localtunnels_greyware_tool_keyword = "e9672eb5f7ced453ef15ebd7a395be9c56c7ce750453883c7bc9e39005035a94" nocase ascii wide
                        $string12_Rust_Localtunnels_greyware_tool_keyword = "fd4b050e4400d57c5f222ce3647debb140ef6fd3176c576fbbe63f856926aa2e" nocase ascii wide
                        $string13_Rust_Localtunnels_greyware_tool_keyword = /https\:\/\/crates\.io\/crates\/localtunnel\-client/ nocase ascii wide
                        $string14_Rust_Localtunnels_greyware_tool_keyword = /https\:\/\/crates\.io\/crates\/localtunnel\-server/ nocase ascii wide
                        $string15_Rust_Localtunnels_greyware_tool_keyword = "kaichaosun/rlt" nocase ascii wide
                        $string16_Rust_Localtunnels_greyware_tool_keyword = "localtunnel client --host " nocase ascii wide
                        $string17_Rust_Localtunnels_greyware_tool_keyword = "localtunnel server --domain " nocase ascii wide
                        $string18_Rust_Localtunnels_greyware_tool_keyword = "Server running at http://localhost:" nocase ascii wide
                        $string19_Rust_Localtunnels_greyware_tool_keyword = "use localtunnel_client::" nocase ascii wide
                        $string20_Rust_Localtunnels_greyware_tool_keyword = "use localtunnel_server::" nocase ascii wide

    condition:
        any of them
}