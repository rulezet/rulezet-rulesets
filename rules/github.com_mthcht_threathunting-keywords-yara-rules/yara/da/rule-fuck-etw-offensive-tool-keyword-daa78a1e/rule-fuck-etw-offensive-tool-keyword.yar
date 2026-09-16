rule rule_Fuck_Etw_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Fuck-Etw' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fuck-Etw"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Fuck_Etw_offensive_tool_keyword = /\/etw\-fuck\.cpp/ nocase ascii wide
                        $string2_Fuck_Etw_offensive_tool_keyword = /\/etw\-fuck\.exe/ nocase ascii wide
                        $string3_Fuck_Etw_offensive_tool_keyword = /\/Fuck\-Etw\.git/ nocase ascii wide
                        $string4_Fuck_Etw_offensive_tool_keyword = /\[\#\]\sReady\sFor\sETW\sPatch\./ nocase ascii wide
                        $string5_Fuck_Etw_offensive_tool_keyword = /\[\+\]\sETW\sPatched.{0,1000}\sNo\sLogs\sNo\sCrime\s\!/ nocase ascii wide
                        $string6_Fuck_Etw_offensive_tool_keyword = /\[i\]\sHooked\sNtdll\sBase\sAddress\s\:\s/ nocase ascii wide
                        $string7_Fuck_Etw_offensive_tool_keyword = /\[i\]\sUnhooked\sNtdll\sBase\sAddress\:\s/ nocase ascii wide
                        $string8_Fuck_Etw_offensive_tool_keyword = /\\etw\-fuck\.cpp/ nocase ascii wide
                        $string9_Fuck_Etw_offensive_tool_keyword = /\\etw\-fuck\.exe/ nocase ascii wide
                        $string10_Fuck_Etw_offensive_tool_keyword = "40E7714F-460D-4CA6-9A5A-FB32C6769BE4" nocase ascii wide
                        $string11_Fuck_Etw_offensive_tool_keyword = /etw\-fuck\.exe\s/ nocase ascii wide
                        $string12_Fuck_Etw_offensive_tool_keyword = "Fuck-Etw-main" nocase ascii wide
                        $string13_Fuck_Etw_offensive_tool_keyword = "unkvolism/Fuck-Etw" nocase ascii wide

    condition:
        any of them
}