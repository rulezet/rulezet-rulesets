rule HellsHall
{
    meta:
        description = "Detection patterns for the tool 'HellsHall' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HellsHall"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/HellHall\.git/ nocase ascii wide
                        $string2 = /\/HellsHall\.exe/ nocase ascii wide
                        $string3 = /\[\#\]\s\[HELL\sHALL\]\sPress\s\<Enter\>\sTo\sQUIT\s\.\.\.\s/ nocase ascii wide
                        $string4 = /\[\+\]\s\[HELL\sHALL\]\spAddress\s\:\s/ nocase ascii wide
                        $string5 = /\[i\]\s\[HELL\sHALL\]\sPress\s\<Enter\>\sTo\sRun\s\.\.\.\s/ nocase ascii wide
                        $string6 = /\\AsmHell\.asm/ nocase ascii wide
                        $string7 = /\\HellsHall\.c/ nocase ascii wide
                        $string8 = /\\HellsHall\.exe/ nocase ascii wide
                        $string9 = /\\HellsHall\.h/ nocase ascii wide
                        $string10 = "F06EAC7B-6996-4E78-B045-0DF6ED201367" nocase ascii wide
                        $string11 = /HellHall\-main\.zip/ nocase ascii wide
                        $string12 = /Hell\'sHall\.vcxproj/ nocase ascii wide
                        $string13 = /Hell\'sHall\-Clang\&NoCrt\.zip/ nocase ascii wide
                        $string14 = "Maldev-Academy/HellHall" nocase ascii wide

    condition:
        any of them
}