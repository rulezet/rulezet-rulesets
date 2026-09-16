rule rule_PEASS_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'PEASS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PEASS"
        rule_category = "signature_keyword"

    strings:
                        $string1_PEASS_signature_keyword = /VirTool\:MSIL\/Aikaantivm\.GG\!MTB/ nocase ascii wide

    condition:
        any of them
}