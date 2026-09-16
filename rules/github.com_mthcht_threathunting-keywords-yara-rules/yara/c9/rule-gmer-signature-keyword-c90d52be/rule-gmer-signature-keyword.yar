rule rule_gmer_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'gmer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gmer"
        rule_category = "signature_keyword"

    strings:
                        $string1_gmer_signature_keyword = "HackTool:Win32/Gmer" nocase ascii wide

    condition:
        any of them
}