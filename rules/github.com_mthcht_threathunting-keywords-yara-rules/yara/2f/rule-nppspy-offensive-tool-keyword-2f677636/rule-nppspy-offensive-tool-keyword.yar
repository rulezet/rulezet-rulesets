rule rule_NPPSpy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NPPSpy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NPPSpy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NPPSpy_offensive_tool_keyword = /\/NPPSPY\.dll/ nocase ascii wide
                        $string2_NPPSpy_offensive_tool_keyword = /\/NPPSpy\.exe/ nocase ascii wide
                        $string3_NPPSpy_offensive_tool_keyword = /\/PSPY\.dll/ nocase ascii wide
                        $string4_NPPSpy_offensive_tool_keyword = /\\NPPSpy\.c/ nocase ascii wide
                        $string5_NPPSpy_offensive_tool_keyword = /\\NPPSPY\.dll/ nocase ascii wide
                        $string6_NPPSpy_offensive_tool_keyword = /\\NPPSpy\.exe/ nocase ascii wide
                        $string7_NPPSpy_offensive_tool_keyword = /\\NPPSpy\.txt/ nocase ascii wide
                        $string8_NPPSpy_offensive_tool_keyword = /\\PSPY\.dll/ nocase ascii wide
                        $string9_NPPSpy_offensive_tool_keyword = /\\PSPY\.exe/ nocase ascii wide
                        $string10_NPPSpy_offensive_tool_keyword = /\\StolenPasswords\.txt/ nocase ascii wide

    condition:
        any of them
}