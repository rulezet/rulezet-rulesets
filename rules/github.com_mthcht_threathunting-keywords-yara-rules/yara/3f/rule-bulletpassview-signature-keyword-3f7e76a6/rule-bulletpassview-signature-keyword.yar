rule rule_bulletpassview_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'bulletpassview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bulletpassview"
        rule_category = "signature_keyword"

    strings:
                        $string1_bulletpassview_signature_keyword = "HackTool:Win32/Passview!MSR" nocase ascii wide
                        $string2_bulletpassview_signature_keyword = "HTool-PassView" nocase ascii wide
                        $string3_bulletpassview_signature_keyword = /NirPassView\s\(PUA\)/ nocase ascii wide

    condition:
        any of them
}