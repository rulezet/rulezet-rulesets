rule rule_Adzok_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Adzok' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adzok"
        rule_category = "signature_keyword"

    strings:
                        $string1_Adzok_signature_keyword = /A\sVariant\sOf\sJava\/Adwind\.SN/ nocase ascii wide
                        $string2_Adzok_signature_keyword = "Adwind!jar" nocase ascii wide

    condition:
        any of them
}