rule Amnesiac
{
    meta:
        description = "Detection patterns for the tool 'Amnesiac' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amnesiac"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /VirTool\:PowerShell\/Dipadz\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}