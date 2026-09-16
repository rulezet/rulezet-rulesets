rule rule_Dumpert_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Dumpert' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dumpert"
        rule_category = "signature_keyword"

    strings:
                        $string1_Dumpert_signature_keyword = "Win64/Outflank" nocase ascii wide

    condition:
        any of them
}