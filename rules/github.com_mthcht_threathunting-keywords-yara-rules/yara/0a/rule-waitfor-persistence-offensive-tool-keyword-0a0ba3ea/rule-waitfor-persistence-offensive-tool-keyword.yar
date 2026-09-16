rule rule_Waitfor_Persistence_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Waitfor-Persistence' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Waitfor-Persistence"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Waitfor_Persistence_offensive_tool_keyword = /\sUse\-Waitfor\.exe/ nocase ascii wide
                        $string2_Waitfor_Persistence_offensive_tool_keyword = /\sWaitfor\-Persistence\.ps1/ nocase ascii wide
                        $string3_Waitfor_Persistence_offensive_tool_keyword = /\/Use\-Waitfor\.exe/ nocase ascii wide
                        $string4_Waitfor_Persistence_offensive_tool_keyword = /\/Waitfor\-Persistence\.git/ nocase ascii wide
                        $string5_Waitfor_Persistence_offensive_tool_keyword = /\/Waitfor\-Persistence\.ps1/ nocase ascii wide
                        $string6_Waitfor_Persistence_offensive_tool_keyword = /\\Use\-Waitfor\.exe/ nocase ascii wide
                        $string7_Waitfor_Persistence_offensive_tool_keyword = /\\Waitfor\-Persistence\.ps1/ nocase ascii wide
                        $string8_Waitfor_Persistence_offensive_tool_keyword = /\\Waitfor\-Persistence\\/ nocase ascii wide
                        $string9_Waitfor_Persistence_offensive_tool_keyword = /\\Waitfor\-Persistence\-master/ nocase ascii wide
                        $string10_Waitfor_Persistence_offensive_tool_keyword = "3gstudent/Waitfor-Persistence" nocase ascii wide
                        $string11_Waitfor_Persistence_offensive_tool_keyword = "fcda7875e75e4d74879ad122a5861477e30c825cb90aceb76ac885cc2eb7e6dc" nocase ascii wide
                        $string12_Waitfor_Persistence_offensive_tool_keyword = "JABlAHgAZQBjAD0AKABbAFcAbQBpAEMAbABhAHMAcwBdACAAJwBXAGkAbgAzADIAXwBCAGEAYwBrAGQAbwBvAHIAJwApAC4AUAByAG8AcABlAHIAdABpAGUAcwBbACcAQwBvAGQAZQAnAF0ALgBWAGEAbAB1AGUAOwAgAGkAZQB4ACAAJABlAHgAZQBjAA" nocase ascii wide
                        $string13_Waitfor_Persistence_offensive_tool_keyword = "'Win32_Backdoor'" nocase ascii wide

    condition:
        any of them
}