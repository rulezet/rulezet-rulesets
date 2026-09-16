rule rule_NTLMRelay2Self_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NTLMRelay2Self' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTLMRelay2Self"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NTLMRelay2Self_offensive_tool_keyword = "/NTLMRelay2Self" nocase ascii wide
                        $string2_NTLMRelay2Self_offensive_tool_keyword = /\\NTLMRelay2Self/ nocase ascii wide
                        $string3_NTLMRelay2Self_offensive_tool_keyword = /inline\-execute\sStartWebClientSvc\.x64\.o/ nocase ascii wide
                        $string4_NTLMRelay2Self_offensive_tool_keyword = /NTLMRelay2Self\.git/ nocase ascii wide

    condition:
        any of them
}