rule rule_Carbanak_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Carbanak' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Carbanak"
        rule_category = "signature_keyword"

    strings:
                        $string1_Carbanak_signature_keyword = /Backdoor\.Win32\.CARBANAK\.A/ nocase ascii wide
                        $string2_Carbanak_signature_keyword = "Troj/Carbanak-" nocase ascii wide
                        $string3_Carbanak_signature_keyword = /Trojan\.Carberp\.B\!g1/ nocase ascii wide

    condition:
        any of them
}