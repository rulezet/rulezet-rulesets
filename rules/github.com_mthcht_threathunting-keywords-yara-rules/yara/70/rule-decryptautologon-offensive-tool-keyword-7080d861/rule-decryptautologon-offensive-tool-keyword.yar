rule rule_DecryptAutoLogon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DecryptAutoLogon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DecryptAutoLogon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DecryptAutoLogon_offensive_tool_keyword = /\/DecryptAutoLogon\.exe/ nocase ascii wide
                        $string2_DecryptAutoLogon_offensive_tool_keyword = /\/DecryptAutoLogon\.git/ nocase ascii wide
                        $string3_DecryptAutoLogon_offensive_tool_keyword = /\\DecryptAutoLogon\.exe/ nocase ascii wide
                        $string4_DecryptAutoLogon_offensive_tool_keyword = /\\DecryptAutoLogon\.sln/ nocase ascii wide
                        $string5_DecryptAutoLogon_offensive_tool_keyword = /\\DecryptAutoLogon\.sln/ nocase ascii wide
                        $string6_DecryptAutoLogon_offensive_tool_keyword = /\\DecryptAutoLogon\-main/ nocase ascii wide
                        $string7_DecryptAutoLogon_offensive_tool_keyword = ">DecryptAutoLogon<" nocase ascii wide
                        $string8_DecryptAutoLogon_offensive_tool_keyword = "015A37FC-53D0-499B-BFFE-AB88C5086040" nocase ascii wide
                        $string9_DecryptAutoLogon_offensive_tool_keyword = "6f14aa417bc4b85c47ef65bfed84e2b7728b1cb8bdd1c0cfc6eb6cd7fd0db7c0" nocase ascii wide
                        $string10_DecryptAutoLogon_offensive_tool_keyword = "83b65d33d21b01395de5b5537e36f18eb8f16237a64f3a8f17991dc652d1a61a" nocase ascii wide
                        $string11_DecryptAutoLogon_offensive_tool_keyword = "83b65d33d21b01395de5b5537e36f18eb8f16237a64f3a8f17991dc652d1a61a" nocase ascii wide
                        $string12_DecryptAutoLogon_offensive_tool_keyword = "9b723acfd67b3a99b88251493db23b8af6fedc8e36395096acec7332f61b86ba" nocase ascii wide
                        $string13_DecryptAutoLogon_offensive_tool_keyword = "c749894ea43c267418df93c7dd6b74ef25826d6c4a5461226ec800ae2efd1921" nocase ascii wide
                        $string14_DecryptAutoLogon_offensive_tool_keyword = "securesean/DecryptAutoLogon" nocase ascii wide

    condition:
        any of them
}