rule Fuck_Etw
{
    meta:
        description = "Detection patterns for the tool 'Fuck-Etw' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fuck-Etw"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/etw\-fuck\.cpp/ nocase ascii wide
                        $string2 = /\/etw\-fuck\.exe/ nocase ascii wide
                        $string3 = /\/Fuck\-Etw\.git/ nocase ascii wide
                        $string4 = /\[\#\]\sReady\sFor\sETW\sPatch\./ nocase ascii wide
                        $string5 = /\[\+\]\sETW\sPatched.{0,1000}\sNo\sLogs\sNo\sCrime\s\!/ nocase ascii wide
                        $string6 = /\[i\]\sHooked\sNtdll\sBase\sAddress\s\:\s/ nocase ascii wide
                        $string7 = /\[i\]\sUnhooked\sNtdll\sBase\sAddress\:\s/ nocase ascii wide
                        $string8 = /\\etw\-fuck\.cpp/ nocase ascii wide
                        $string9 = /\\etw\-fuck\.exe/ nocase ascii wide
                        $string10 = "40E7714F-460D-4CA6-9A5A-FB32C6769BE4" nocase ascii wide
                        $string11 = /etw\-fuck\.exe\s/ nocase ascii wide
                        $string12 = "Fuck-Etw-main" nocase ascii wide
                        $string13 = "unkvolism/Fuck-Etw" nocase ascii wide

    condition:
        any of them
}