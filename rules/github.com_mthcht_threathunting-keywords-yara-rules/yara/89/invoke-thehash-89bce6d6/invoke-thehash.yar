rule Invoke_TheHash
{
    meta:
        description = "Detection patterns for the tool 'Invoke-TheHash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-TheHash"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "Trojan:Win32/Ceevee" nocase ascii wide

    condition:
        any of them
}