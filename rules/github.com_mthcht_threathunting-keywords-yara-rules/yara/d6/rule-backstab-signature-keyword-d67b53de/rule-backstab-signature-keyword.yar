rule rule_Backstab_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Backstab' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Backstab"
        rule_category = "signature_keyword"

    strings:
                        $string1_Backstab_signature_keyword = "VirTool:Win64/Backstab" nocase ascii wide

    condition:
        any of them
}