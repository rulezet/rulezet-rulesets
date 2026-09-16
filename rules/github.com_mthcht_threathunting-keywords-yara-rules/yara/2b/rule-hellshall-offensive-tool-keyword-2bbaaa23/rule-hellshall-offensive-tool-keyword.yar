rule rule_HellsHall_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HellsHall' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HellsHall"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HellsHall_offensive_tool_keyword = /\/HellHall\.git/ nocase ascii wide
                        $string2_HellsHall_offensive_tool_keyword = /\/HellsHall\.exe/ nocase ascii wide
                        $string3_HellsHall_offensive_tool_keyword = /\[\#\]\s\[HELL\sHALL\]\sPress\s\<Enter\>\sTo\sQUIT\s\.\.\.\s/ nocase ascii wide
                        $string4_HellsHall_offensive_tool_keyword = /\[\+\]\s\[HELL\sHALL\]\spAddress\s\:\s/ nocase ascii wide
                        $string5_HellsHall_offensive_tool_keyword = /\[i\]\s\[HELL\sHALL\]\sPress\s\<Enter\>\sTo\sRun\s\.\.\.\s/ nocase ascii wide
                        $string6_HellsHall_offensive_tool_keyword = /\\AsmHell\.asm/ nocase ascii wide
                        $string7_HellsHall_offensive_tool_keyword = /\\HellsHall\.c/ nocase ascii wide
                        $string8_HellsHall_offensive_tool_keyword = /\\HellsHall\.exe/ nocase ascii wide
                        $string9_HellsHall_offensive_tool_keyword = /\\HellsHall\.h/ nocase ascii wide
                        $string10_HellsHall_offensive_tool_keyword = "F06EAC7B-6996-4E78-B045-0DF6ED201367" nocase ascii wide
                        $string11_HellsHall_offensive_tool_keyword = /HellHall\-main\.zip/ nocase ascii wide
                        $string12_HellsHall_offensive_tool_keyword = /Hell\'sHall\.vcxproj/ nocase ascii wide
                        $string13_HellsHall_offensive_tool_keyword = /Hell\'sHall\-Clang\&NoCrt\.zip/ nocase ascii wide
                        $string14_HellsHall_offensive_tool_keyword = "Maldev-Academy/HellHall" nocase ascii wide

    condition:
        any of them
}