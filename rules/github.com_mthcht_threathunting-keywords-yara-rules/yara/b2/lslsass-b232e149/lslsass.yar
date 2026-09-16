rule lslsass
{
    meta:
        description = "Detection patterns for the tool 'lslsass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lslsass"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Hacktool\.PTHToolkit/ nocase ascii wide
                        $string2 = "HKTL_PTHTOOLKIT" nocase ascii wide

    condition:
        any of them
}