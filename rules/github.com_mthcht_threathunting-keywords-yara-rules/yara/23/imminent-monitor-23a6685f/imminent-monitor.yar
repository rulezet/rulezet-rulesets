rule Imminent_Monitor
{
    meta:
        description = "Detection patterns for the tool 'Imminent-Monitor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Imminent-Monitor"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Win\.Packed\.Immirat\-/ nocase ascii wide

    condition:
        any of them
}