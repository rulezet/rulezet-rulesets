rule rule_Sandman_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Sandman' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sandman"
        rule_category = "signature_keyword"

    strings:
                        $string1_Sandman_signature_keyword = "ATK/Sandman-A" nocase ascii wide
                        $string2_Sandman_signature_keyword = /Backdoor\.MSIL\.Sandman/ nocase ascii wide
                        $string3_Sandman_signature_keyword = /VirTool\:MSIL\/Sabakz\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}