rule NtlmThief
{
    meta:
        description = "Detection patterns for the tool 'NtlmThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtlmThief"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HEUR\:Trojan\-PSW\.Win64\.NTLM\.gen/ nocase ascii wide

    condition:
        any of them
}