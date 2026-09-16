rule rule_NTLMSleuth_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NTLMSleuth' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTLMSleuth"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NTLMSleuth_offensive_tool_keyword = /\/NTLMSleuth\.git/ nocase ascii wide
                        $string2_NTLMSleuth_offensive_tool_keyword = /https\:\/\/ntlm\.pw\// nocase ascii wide
                        $string3_NTLMSleuth_offensive_tool_keyword = "jmarr73/NTLMSleuth" nocase ascii wide
                        $string4_NTLMSleuth_offensive_tool_keyword = /NTLMSleuth\.ps1/ nocase ascii wide
                        $string5_NTLMSleuth_offensive_tool_keyword = /NTLMSleuth\.sh/ nocase ascii wide

    condition:
        any of them
}