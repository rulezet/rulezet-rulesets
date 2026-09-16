rule POC
{
    meta:
        description = "Detection patterns for the tool 'POC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "POC"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Trojan\:Win64\/CryptInject\.XY\!MTB/ nocase ascii wide

    condition:
        any of them
}