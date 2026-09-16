rule AtomLdr
{
    meta:
        description = "Detection patterns for the tool 'AtomLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AtomLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/AtomLdr\.git/ nocase ascii wide
                        $string2 = /\\AtomLdr\\x64/ nocase ascii wide
                        $string3 = /AtomLdr\.dll/ nocase ascii wide
                        $string4 = /AtomLdr\.sln/ nocase ascii wide
                        $string5 = /AtomLdr\.vcxproj/ nocase ascii wide
                        $string6 = /AtomLdr\-main\.zip/ nocase ascii wide
                        $string7 = "NUL0x4C/AtomLdr" nocase ascii wide

    condition:
        any of them
}