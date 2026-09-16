rule rule_adrecon_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'adrecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adrecon"
        rule_category = "signature_keyword"

    strings:
                        $string1_adrecon_signature_keyword = "HackTool:PowerShell/ADRecon" nocase ascii wide

    condition:
        any of them
}