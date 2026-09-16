rule rule_subbrute_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'subbrute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "subbrute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_subbrute_offensive_tool_keyword = /\ssubbrute\.py/ nocase ascii wide
                        $string2_subbrute_offensive_tool_keyword = /\ssubbrute\.run\(/ nocase ascii wide
                        $string3_subbrute_offensive_tool_keyword = /\/subbrute\.git/ nocase ascii wide
                        $string4_subbrute_offensive_tool_keyword = /\/subbrute\.py/ nocase ascii wide
                        $string5_subbrute_offensive_tool_keyword = "/subbrute/releases/download/" nocase ascii wide
                        $string6_subbrute_offensive_tool_keyword = /\\subbrute\.py/ nocase ascii wide
                        $string7_subbrute_offensive_tool_keyword = "0901aac4feb3ef12677e64599acc30daf72ab2e3227ab46db8b06a6e8a5c2070" nocase ascii wide
                        $string8_subbrute_offensive_tool_keyword = "0e0ea3fcb913470c6f7814cc1d943d51f687578f2d59a1a15101587cb0ff709d" nocase ascii wide
                        $string9_subbrute_offensive_tool_keyword = "340ced72dda48a480d8a7d3f4e4d55af5de3f32bd61806362c04b7081bb11607" nocase ascii wide
                        $string10_subbrute_offensive_tool_keyword = "34aa130f8c55629bb00cad0d4834c274b5408cabd49579ee3d75d2cf5054ba9e" nocase ascii wide
                        $string11_subbrute_offensive_tool_keyword = "4ab4e04a014333fd820edebcd24b0fa920390d312f951bcf3cc1a7733baecdb8" nocase ascii wide
                        $string12_subbrute_offensive_tool_keyword = "58c2cf7ff89c1fc1871e507f0c1a467dcf37b45d094d73c61b0ded0f935eec98" nocase ascii wide
                        $string13_subbrute_offensive_tool_keyword = "7d90e68af91d2670512ca9db8d6c6d1055007918ca637b9ae54f39f0380ad2e3" nocase ascii wide
                        $string14_subbrute_offensive_tool_keyword = "7ee2ae92197926fc349bebbf9c6065aa54f994234d543a58725f4dda99699afa" nocase ascii wide
                        $string15_subbrute_offensive_tool_keyword = "import subbrute" nocase ascii wide
                        $string16_subbrute_offensive_tool_keyword = /subbrute\.exe/ nocase ascii wide
                        $string17_subbrute_offensive_tool_keyword = /subbrute\.py\s\-/ nocase ascii wide
                        $string18_subbrute_offensive_tool_keyword = /subbrute_windows\.zip/ nocase ascii wide
                        $string19_subbrute_offensive_tool_keyword = "TheRook/subbrute" nocase ascii wide
                        $string20_subbrute_offensive_tool_keyword = /windows\-subbrute\.zip/ nocase ascii wide

    condition:
        any of them
}