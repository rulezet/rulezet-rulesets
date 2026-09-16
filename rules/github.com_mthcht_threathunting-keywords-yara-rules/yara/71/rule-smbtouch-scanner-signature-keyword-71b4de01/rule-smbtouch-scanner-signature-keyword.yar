rule rule_Smbtouch_Scanner_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Smbtouch-Scanner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Smbtouch-Scanner"
        rule_category = "signature_keyword"

    strings:
                        $string1_Smbtouch_Scanner_signature_keyword = /HackTool\.Equation/ nocase ascii wide
                        $string2_Smbtouch_Scanner_signature_keyword = "Trojan:Win32/Eqtonex!rfn" nocase ascii wide

    condition:
        any of them
}