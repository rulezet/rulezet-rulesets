rule rule_SharpLocker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpLocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpLocker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpLocker_offensive_tool_keyword = /\/SharpLocker\.exe/ nocase ascii wide
                        $string2_SharpLocker_offensive_tool_keyword = /\/SharpLocker\.git/ nocase ascii wide
                        $string3_SharpLocker_offensive_tool_keyword = "/SharpLocker/releases/" nocase ascii wide
                        $string4_SharpLocker_offensive_tool_keyword = "/SharpLocker/zipball/" nocase ascii wide
                        $string5_SharpLocker_offensive_tool_keyword = /\\SharpLocker\.csproj/ nocase ascii wide
                        $string6_SharpLocker_offensive_tool_keyword = /\\SharpLocker\.exe/ nocase ascii wide
                        $string7_SharpLocker_offensive_tool_keyword = /\\SharpLocker\-master/ nocase ascii wide
                        $string8_SharpLocker_offensive_tool_keyword = ">SharpLocker<" nocase ascii wide
                        $string9_SharpLocker_offensive_tool_keyword = "10755f01684f2dfa48f5f096748c00ee21c272a8f1a558b021dc9a8298f3cc25" nocase ascii wide
                        $string10_SharpLocker_offensive_tool_keyword = "2b2b84ccdf5351dab81dbd87860fcfbf61bf44a88fb547a7f4a3cc71667c7362" nocase ascii wide
                        $string11_SharpLocker_offensive_tool_keyword = "2fbc59378c66069942a5b99d32551d080f7f8a984e568c7b408e6c7b67bdebff" nocase ascii wide
                        $string12_SharpLocker_offensive_tool_keyword = "4d5ee19778d34bdddd4c391ed860d10d2d3a46c22090fa0e701e263bec6bca2c" nocase ascii wide
                        $string13_SharpLocker_offensive_tool_keyword = "6126c4f3c62340df9f501ef98b7266ef2b0fd668a9b286d4bc36eff5e46095bc" nocase ascii wide
                        $string14_SharpLocker_offensive_tool_keyword = "6e7d2c54b036019f32df4238d9f26e97efe246df82c687ee8033c7c9fe5a9f09" nocase ascii wide
                        $string15_SharpLocker_offensive_tool_keyword = "713c7d03ee5e75b2cacae76a91418ce7855faf39c485f97aed1e277bab87de47" nocase ascii wide
                        $string16_SharpLocker_offensive_tool_keyword = "A6F8500F-68BC-4EFC-962A-6C6E68D893AF" nocase ascii wide
                        $string17_SharpLocker_offensive_tool_keyword = "Performing attack with current NTLM settings on current user" nocase ascii wide
                        $string18_SharpLocker_offensive_tool_keyword = "Pickfordmatt/SharpLocker" nocase ascii wide

    condition:
        any of them
}