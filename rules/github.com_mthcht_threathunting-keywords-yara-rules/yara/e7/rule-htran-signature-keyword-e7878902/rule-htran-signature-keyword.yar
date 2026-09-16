rule rule_htran_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'htran' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "htran"
        rule_category = "signature_keyword"

    strings:
                        $string1_htran_signature_keyword = /Hacktool\.HTran\./ nocase ascii wide
                        $string2_htran_signature_keyword = "HackTool:Win32/Htran" nocase ascii wide
                        $string3_htran_signature_keyword = "HKTL_HTRAN" nocase ascii wide
                        $string4_htran_signature_keyword = "Riskware/Htran" nocase ascii wide
                        $string5_htran_signature_keyword = /Win32\/HackTool\.Hucline\.F/ nocase ascii wide

    condition:
        any of them
}