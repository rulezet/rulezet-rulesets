rule Decrypt_RDCMan
{
    meta:
        description = "Detection patterns for the tool 'Decrypt-RDCMan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Decrypt-RDCMan"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.DecryptRDCMan/ nocase ascii wide
                        $string2 = "HackTool:PowerShell/DecryptRDCMan" nocase ascii wide

    condition:
        any of them
}