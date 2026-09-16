rule rule_EternalBlack_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'EternalBlack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EternalBlack"
        rule_category = "signature_keyword"

    strings:
                        $string1_EternalBlack_signature_keyword = /Trojan\.Meterpreter/ nocase ascii wide
                        $string2_EternalBlack_signature_keyword = "Trojan:Win64/Meterpreter" nocase ascii wide

    condition:
        any of them
}