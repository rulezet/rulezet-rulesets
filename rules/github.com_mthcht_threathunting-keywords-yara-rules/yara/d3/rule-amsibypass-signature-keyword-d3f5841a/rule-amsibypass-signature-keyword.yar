rule rule_AmsiBypass_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'AmsiBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AmsiBypass"
        rule_category = "signature_keyword"

    strings:
                        $string1_AmsiBypass_signature_keyword = /\/AmsiTamper\./

    condition:
        any of them
}