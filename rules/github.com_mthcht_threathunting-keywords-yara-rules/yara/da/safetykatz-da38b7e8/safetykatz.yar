rule SafetyKatz
{
    meta:
        description = "Detection patterns for the tool 'SafetyKatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SafetyKatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SafetyKatz\.git/ nocase ascii wide
                        $string2 = /\\SafetyKatz/ nocase ascii wide
                        $string3 = /\]\sExecuting\sloaded\sMimikatz\sPE/ nocase ascii wide
                        $string4 = "387930bab7650291baada3b39dc55167c1e6f1fd2154de61f77e07bd14c8b9bc" nocase ascii wide
                        $string5 = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" nocase ascii wide
                        $string6 = "GhostPack/SafetyKatz" nocase ascii wide
                        $string7 = /SafetyKatz\.csproj/ nocase ascii wide
                        $string8 = /SafetyKatz\.exe/ nocase ascii wide
                        $string9 = /SafetyKatz\.sln/ nocase ascii wide
                        $string10 = "SafetyKatz-master" nocase ascii wide

    condition:
        any of them
}