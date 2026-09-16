rule rule_Decrypt_RDCMan_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Decrypt-RDCMan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Decrypt-RDCMan"
        rule_category = "signature_keyword"

    strings:
                        $string1_Decrypt_RDCMan_signature_keyword = /HackTool\.DecryptRDCMan/ nocase ascii wide
                        $string2_Decrypt_RDCMan_signature_keyword = "HackTool:PowerShell/DecryptRDCMan" nocase ascii wide

    condition:
        any of them
}