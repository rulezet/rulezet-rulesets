rule NTLMSleuth
{
    meta:
        description = "Detection patterns for the tool 'NTLMSleuth' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTLMSleuth"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/NTLMSleuth\.git/ nocase ascii wide
                        $string2 = /https\:\/\/ntlm\.pw\// nocase ascii wide
                        $string3 = "jmarr73/NTLMSleuth" nocase ascii wide
                        $string4 = /NTLMSleuth\.ps1/ nocase ascii wide
                        $string5 = /NTLMSleuth\.sh/ nocase ascii wide

    condition:
        any of them
}