rule rule_LaZagne_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'LaZagne' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LaZagne"
        rule_category = "signature_keyword"

    strings:
                        $string1_LaZagne_signature_keyword = /Hacktool\.Lazagne/ nocase ascii wide
                        $string2_LaZagne_signature_keyword = "HTool-Lazagne" nocase ascii wide
                        $string3_LaZagne_signature_keyword = /Trojan\.Lazagne/ nocase ascii wide
                        $string4_LaZagne_signature_keyword = /Win32\.LaZagne/ nocase ascii wide
                        $string5_LaZagne_signature_keyword = /Win64\.Lazagne/ nocase ascii wide

    condition:
        any of them
}