rule rule_Invoke_TheHash_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-TheHash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-TheHash"
        rule_category = "signature_keyword"

    strings:
                        $string1_Invoke_TheHash_signature_keyword = "Trojan:Win32/Ceevee" nocase ascii wide

    condition:
        any of them
}