rule PCHunter
{
    meta:
        description = "Detection patterns for the tool 'PCHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PCHunter"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /PUA\.Win64\.PCHunter\.YACIU/ nocase ascii wide
                        $string2 = /RiskWare\.PcHunter/ nocase ascii wide

    condition:
        any of them
}