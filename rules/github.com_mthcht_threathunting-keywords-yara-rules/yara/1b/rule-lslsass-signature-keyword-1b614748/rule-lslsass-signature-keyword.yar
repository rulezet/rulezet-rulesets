rule rule_lslsass_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'lslsass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lslsass"
        rule_category = "signature_keyword"

    strings:
                        $string1_lslsass_signature_keyword = /Hacktool\.PTHToolkit/ nocase ascii wide
                        $string2_lslsass_signature_keyword = "HKTL_PTHTOOLKIT" nocase ascii wide

    condition:
        any of them
}