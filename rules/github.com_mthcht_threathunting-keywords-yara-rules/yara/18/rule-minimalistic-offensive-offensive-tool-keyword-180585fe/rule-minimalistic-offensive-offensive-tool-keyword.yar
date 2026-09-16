rule rule_Minimalistic_offensive_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Minimalistic-offensive' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Minimalistic-offensive"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Minimalistic_offensive_offensive_tool_keyword = "# Minimalistic AD login bruteforcer " nocase ascii wide
                        $string2_Minimalistic_offensive_offensive_tool_keyword = "# Minimalistic SMB login bruteforcer " nocase ascii wide
                        $string3_Minimalistic_offensive_offensive_tool_keyword = "# Minimalistic TCP and UDP port scanners" nocase ascii wide
                        $string4_Minimalistic_offensive_offensive_tool_keyword = /\/adlogin\.ps1/ nocase ascii wide
                        $string5_Minimalistic_offensive_offensive_tool_keyword = /\/localbrute\.ps1/ nocase ascii wide
                        $string6_Minimalistic_offensive_offensive_tool_keyword = /\/localbrute\-extra\-mini\.ps1/ nocase ascii wide
                        $string7_Minimalistic_offensive_offensive_tool_keyword = /\/Minimalistic\-offensive\-security\-tools\.git/ nocase ascii wide
                        $string8_Minimalistic_offensive_offensive_tool_keyword = /\/port\-scan\-tcp\.ps1/ nocase ascii wide
                        $string9_Minimalistic_offensive_offensive_tool_keyword = /\/port\-scan\-udp\.ps1/ nocase ascii wide
                        $string10_Minimalistic_offensive_offensive_tool_keyword = /\/smblogin\.ps1/ nocase ascii wide
                        $string11_Minimalistic_offensive_offensive_tool_keyword = /\\adlogin\.ps1/ nocase ascii wide
                        $string12_Minimalistic_offensive_offensive_tool_keyword = /\\localbrute\.ps1/ nocase ascii wide
                        $string13_Minimalistic_offensive_offensive_tool_keyword = /\\localbrute\-extra\-mini\.ps1/ nocase ascii wide
                        $string14_Minimalistic_offensive_offensive_tool_keyword = /\\port\-scan\-tcp\.ps1/ nocase ascii wide
                        $string15_Minimalistic_offensive_offensive_tool_keyword = /\\port\-scan\-udp\.ps1/ nocase ascii wide
                        $string16_Minimalistic_offensive_offensive_tool_keyword = /\\smblogin\.ps1/ nocase ascii wide
                        $string17_Minimalistic_offensive_offensive_tool_keyword = /\\smblogin\.results\.txt/ nocase ascii wide
                        $string18_Minimalistic_offensive_offensive_tool_keyword = /\\smblogin\-extra\-mini\.ps1/ nocase ascii wide
                        $string19_Minimalistic_offensive_offensive_tool_keyword = "288b02056109591e230be8268e3e41c61f791d0025008050fc1a558118234259" nocase ascii wide
                        $string20_Minimalistic_offensive_offensive_tool_keyword = "374356feb445591acf371af512a66c6197f8a18613f41988cc7357b27c738a94" nocase ascii wide
                        $string21_Minimalistic_offensive_offensive_tool_keyword = "43c40eb82cecff19379a8de93b36686149eded614d1dfbdabd31e3fb9e6f3fc6" nocase ascii wide
                        $string22_Minimalistic_offensive_offensive_tool_keyword = "64005eea1af219477177e1f5a2479f4214705ef814f2ca2e70d921bf696b0808" nocase ascii wide
                        $string23_Minimalistic_offensive_offensive_tool_keyword = "6fb86b256e278c854acf21be16797fb8d774759982cd3251ffda758260dffd44" nocase ascii wide
                        $string24_Minimalistic_offensive_offensive_tool_keyword = "87f28c29263f95595eaa3c35a9091eaa5ccadce9f84738309f8781328465ede2" nocase ascii wide
                        $string25_Minimalistic_offensive_offensive_tool_keyword = "96c4151c60a745d0ad96649cd6589dd28fb8e4761de75a425965315a3aab2d62" nocase ascii wide
                        $string26_Minimalistic_offensive_offensive_tool_keyword = "b4a463948663e6a142ddbbc35f9ef543da818497acfdf21c21ec2bd96bc53fa6" nocase ascii wide
                        $string27_Minimalistic_offensive_offensive_tool_keyword = "InfosecMatter/Minimalistic-offensive-security-tools" nocase ascii wide

    condition:
        any of them
}