rule rule_exe_to_dll_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'exe_to_dll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "exe_to_dll"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_exe_to_dll_offensive_tool_keyword = /\/exe_to_dll\.git/ nocase ascii wide
                        $string2_exe_to_dll_offensive_tool_keyword = /\/exe_to_dll\.git/ nocase ascii wide
                        $string3_exe_to_dll_offensive_tool_keyword = /\/pe2shc\.exe/ nocase ascii wide
                        $string4_exe_to_dll_offensive_tool_keyword = /\\exe_to_dll\\/ nocase ascii wide
                        $string5_exe_to_dll_offensive_tool_keyword = /exe_to_dll\.exe/ nocase ascii wide
                        $string6_exe_to_dll_offensive_tool_keyword = /exe_to_dll\.exe/ nocase ascii wide
                        $string7_exe_to_dll_offensive_tool_keyword = /exe_to_dll_.{0,1000}\.zip/ nocase ascii wide
                        $string8_exe_to_dll_offensive_tool_keyword = /exe_to_dll_.{0,1000}_32bit\.zip/ nocase ascii wide
                        $string9_exe_to_dll_offensive_tool_keyword = /exe_to_dll_.{0,1000}_64bit\.zip/ nocase ascii wide
                        $string10_exe_to_dll_offensive_tool_keyword = "exe_to_dll-master" nocase ascii wide
                        $string11_exe_to_dll_offensive_tool_keyword = "exe_to_dll-master" nocase ascii wide
                        $string12_exe_to_dll_offensive_tool_keyword = "hasherezade/exe_to_dll" nocase ascii wide
                        $string13_exe_to_dll_offensive_tool_keyword = "hasherezade/exe_to_dll" nocase ascii wide

    condition:
        any of them
}