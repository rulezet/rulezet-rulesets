rule rule_DecryptRDCManager_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DecryptRDCManager' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DecryptRDCManager"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DecryptRDCManager_offensive_tool_keyword = /\/DecryptRDCManager\.git/ nocase ascii wide
                        $string2_DecryptRDCManager_offensive_tool_keyword = /\\DecryptRDCManager\.sln/ nocase ascii wide
                        $string3_DecryptRDCManager_offensive_tool_keyword = "af91c925c3a6ba14dea50a5d24593c48cc02e7bfc23b7a02eaf59dd55c3ae6cd" nocase ascii wide
                        $string4_DecryptRDCManager_offensive_tool_keyword = "CF924967-0AEC-43B2-B891-D67B6DB9F523" nocase ascii wide
                        $string5_DecryptRDCManager_offensive_tool_keyword = /Decrypt\-RDCMan\.ps1/ nocase ascii wide
                        $string6_DecryptRDCManager_offensive_tool_keyword = /DecryptRDCManager\.exe/ nocase ascii wide
                        $string7_DecryptRDCManager_offensive_tool_keyword = "mez-0/DecryptRDCManager" nocase ascii wide

    condition:
        any of them
}