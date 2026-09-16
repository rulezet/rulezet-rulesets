rule Adzok
{
    meta:
        description = "Detection patterns for the tool 'Adzok' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adzok"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /A\sVariant\sOf\sJava\/Adwind\.SN/ nocase ascii wide
                        $string2 = "Adwind!jar" nocase ascii wide

    condition:
        any of them
}