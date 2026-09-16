rule rule_darkarmour_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'darkarmour' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "darkarmour"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_darkarmour_offensive_tool_keyword = /\s\-f\s.{0,1000}\.exe\s\-\-encrypt\sxor\s\-\-jmp\s\-o\s.{0,1000}\.exe/ nocase ascii wide
                        $string2_darkarmour_offensive_tool_keyword = /\/darkarmour\.git/ nocase ascii wide
                        $string3_darkarmour_offensive_tool_keyword = /avflagged\.exe/ nocase ascii wide
                        $string4_darkarmour_offensive_tool_keyword = "bats3c/darkarmour" nocase ascii wide
                        $string5_darkarmour_offensive_tool_keyword = /darkarmour\.py/ nocase ascii wide
                        $string6_darkarmour_offensive_tool_keyword = "darkarmour-master" nocase ascii wide
                        $string7_darkarmour_offensive_tool_keyword = /reflct_dll_inject\.exe/ nocase ascii wide
                        $string8_darkarmour_offensive_tool_keyword = /shellcode_dropper\.c/ nocase ascii wide

    condition:
        any of them
}