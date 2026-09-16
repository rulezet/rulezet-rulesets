rule bulletpassview
{
    meta:
        description = "Detection patterns for the tool 'bulletpassview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bulletpassview"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "HackTool:Win32/Passview!MSR" nocase ascii wide
                        $string2 = "HTool-PassView" nocase ascii wide
                        $string3 = /NirPassView\s\(PUA\)/ nocase ascii wide

    condition:
        any of them
}