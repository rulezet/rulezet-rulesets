rule rule_ShadowDumper_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShadowDumper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowDumper"
        rule_category = "signature_keyword"

    strings:
                        $string1_ShadowDumper_signature_keyword = /Win64\.ShadowDumper/ nocase ascii wide

    condition:
        any of them
}