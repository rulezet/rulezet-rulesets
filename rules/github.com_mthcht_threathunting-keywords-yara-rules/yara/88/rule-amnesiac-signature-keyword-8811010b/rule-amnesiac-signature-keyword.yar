rule rule_Amnesiac_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Amnesiac' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amnesiac"
        rule_category = "signature_keyword"

    strings:
                        $string1_Amnesiac_signature_keyword = /VirTool\:PowerShell\/Dipadz\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}