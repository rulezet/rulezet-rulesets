rule rule_powercat_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'powercat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powercat"
        rule_category = "signature_keyword"

    strings:
                        $string1_powercat_signature_keyword = /PowerShell\/ReverseShell\.DR/ nocase ascii wide
                        $string2_powercat_signature_keyword = /Win\.Trojan\.Powercat\-/ nocase ascii wide

    condition:
        any of them
}