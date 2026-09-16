rule rule_Termite_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Termite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Termite"
        rule_category = "signature_keyword"

    strings:
                        $string1_Termite_signature_keyword = /BKDR_TERMITE\.A/ nocase ascii wide
                        $string2_Termite_signature_keyword = "W32/EarthWorm" nocase ascii wide

    condition:
        any of them
}