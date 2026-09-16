rule rule_SafetyKatz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SafetyKatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SafetyKatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SafetyKatz_offensive_tool_keyword = /\/SafetyKatz\.git/ nocase ascii wide
                        $string2_SafetyKatz_offensive_tool_keyword = /\\SafetyKatz/ nocase ascii wide
                        $string3_SafetyKatz_offensive_tool_keyword = /\]\sExecuting\sloaded\sMimikatz\sPE/ nocase ascii wide
                        $string4_SafetyKatz_offensive_tool_keyword = "387930bab7650291baada3b39dc55167c1e6f1fd2154de61f77e07bd14c8b9bc" nocase ascii wide
                        $string5_SafetyKatz_offensive_tool_keyword = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase ascii wide
                        $string6_SafetyKatz_offensive_tool_keyword = "GhostPack/SafetyKatz" nocase ascii wide
                        $string7_SafetyKatz_offensive_tool_keyword = /SafetyKatz\.csproj/ nocase ascii wide
                        $string8_SafetyKatz_offensive_tool_keyword = /SafetyKatz\.exe/ nocase ascii wide
                        $string9_SafetyKatz_offensive_tool_keyword = /SafetyKatz\.sln/ nocase ascii wide
                        $string10_SafetyKatz_offensive_tool_keyword = "SafetyKatz-master" nocase ascii wide

    condition:
        any of them
}