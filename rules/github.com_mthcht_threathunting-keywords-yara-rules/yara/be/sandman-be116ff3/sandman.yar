rule Sandman
{
    meta:
        description = "Detection patterns for the tool 'Sandman' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sandman"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "ATK/Sandman-A" nocase ascii wide
                        $string2 = /Backdoor\.MSIL\.Sandman/ nocase ascii wide
                        $string3 = /VirTool\:MSIL\/Sabakz\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}