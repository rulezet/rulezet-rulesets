rule NPPSpy
{
    meta:
        description = "Detection patterns for the tool 'NPPSpy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NPPSpy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/NPPSPY\.dll/ nocase ascii wide
                        $string2 = /\/NPPSpy\.exe/ nocase ascii wide
                        $string3 = /\/PSPY\.dll/ nocase ascii wide
                        $string4 = /\\NPPSpy\.c/ nocase ascii wide
                        $string5 = /\\NPPSPY\.dll/ nocase ascii wide
                        $string6 = /\\NPPSpy\.exe/ nocase ascii wide
                        $string7 = /\\NPPSpy\.txt/ nocase ascii wide
                        $string8 = /\\PSPY\.dll/ nocase ascii wide
                        $string9 = /\\PSPY\.exe/ nocase ascii wide
                        $string10 = /\\StolenPasswords\.txt/ nocase ascii wide

    condition:
        any of them
}