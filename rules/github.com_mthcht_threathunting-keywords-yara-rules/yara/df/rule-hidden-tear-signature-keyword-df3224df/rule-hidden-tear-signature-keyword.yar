rule rule_hidden_tear_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'hidden-tear' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hidden-tear"
        rule_category = "signature_keyword"

    strings:
                        $string1_hidden_tear_signature_keyword = "hiddentear/msil" nocase ascii wide
                        $string2_hidden_tear_signature_keyword = "MSIL/Hiddentear" nocase ascii wide

    condition:
        any of them
}