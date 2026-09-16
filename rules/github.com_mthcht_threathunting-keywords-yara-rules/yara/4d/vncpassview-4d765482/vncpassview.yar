rule VNCPassView
{
    meta:
        description = "Detection patterns for the tool 'VNCPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VNCPassView"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "HackTool:Win32/Passview!MSR" nocase ascii wide
                        $string2 = /VNCPassView\.exe/ nocase ascii wide

    condition:
        any of them
}