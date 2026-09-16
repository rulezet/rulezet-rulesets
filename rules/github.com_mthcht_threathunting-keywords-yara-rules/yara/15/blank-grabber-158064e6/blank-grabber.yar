rule Blank_Grabber
{
    meta:
        description = "Detection patterns for the tool 'Blank-Grabber' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Blank-Grabber"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Trojan\.PWS\.Stealer\./ nocase ascii wide

    condition:
        any of them
}