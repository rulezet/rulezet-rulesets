rule rule_AtomLdr_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AtomLdr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AtomLdr"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AtomLdr_offensive_tool_keyword = /\/AtomLdr\.git/ nocase ascii wide
                        $string2_AtomLdr_offensive_tool_keyword = /\\AtomLdr\\x64/ nocase ascii wide
                        $string3_AtomLdr_offensive_tool_keyword = /AtomLdr\.dll/ nocase ascii wide
                        $string4_AtomLdr_offensive_tool_keyword = /AtomLdr\.sln/ nocase ascii wide
                        $string5_AtomLdr_offensive_tool_keyword = /AtomLdr\.vcxproj/ nocase ascii wide
                        $string6_AtomLdr_offensive_tool_keyword = /AtomLdr\-main\.zip/ nocase ascii wide
                        $string7_AtomLdr_offensive_tool_keyword = "NUL0x4C/AtomLdr" nocase ascii wide

    condition:
        any of them
}