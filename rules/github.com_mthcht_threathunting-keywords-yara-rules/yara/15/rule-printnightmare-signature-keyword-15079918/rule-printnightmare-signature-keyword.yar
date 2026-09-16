rule rule_PrintNightmare_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'PrintNightmare' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrintNightmare"
        rule_category = "signature_keyword"

    strings:
                        $string1_PrintNightmare_signature_keyword = "Win64/PrintNightmare" nocase ascii wide

    condition:
        any of them
}