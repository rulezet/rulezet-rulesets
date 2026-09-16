rule Termite
{
    meta:
        description = "Detection patterns for the tool 'Termite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Termite"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /BKDR_TERMITE\.A/ nocase ascii wide
                        $string2 = "W32/EarthWorm" nocase ascii wide

    condition:
        any of them
}