rule rule_NtlmThief_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'NtlmThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtlmThief"
        rule_category = "signature_keyword"

    strings:
                        $string1_NtlmThief_signature_keyword = /HEUR\:Trojan\-PSW\.Win64\.NTLM\.gen/ nocase ascii wide

    condition:
        any of them
}