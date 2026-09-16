rule Waitfor_Persistence
{
    meta:
        description = "Detection patterns for the tool 'Waitfor-Persistence' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Waitfor-Persistence"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sUse\-Waitfor\.exe/ nocase ascii wide
                        $string2 = /\sWaitfor\-Persistence\.ps1/ nocase ascii wide
                        $string3 = /\/Use\-Waitfor\.exe/ nocase ascii wide
                        $string4 = /\/Waitfor\-Persistence\.git/ nocase ascii wide
                        $string5 = /\/Waitfor\-Persistence\.ps1/ nocase ascii wide
                        $string6 = /\\Use\-Waitfor\.exe/ nocase ascii wide
                        $string7 = /\\Waitfor\-Persistence\.ps1/ nocase ascii wide
                        $string8 = /\\Waitfor\-Persistence\\/ nocase ascii wide
                        $string9 = /\\Waitfor\-Persistence\-master/ nocase ascii wide
                        $string10 = "3gstudent/Waitfor-Persistence" nocase ascii wide
                        $string11 = "fcda7875e75e4d74879ad122a5861477e30c825cb90aceb76ac885cc2eb7e6dc" nocase ascii wide
                        $string12 = "JABlAHgAZQBjAD0AKABbAFcAbQBpAEMAbABhAHMAcwBdACAAJwBXAGkAbgAzADIAXwBCAGEAYwBrAGQAbwBvAHIAJwApAC4AUAByAG8AcABlAHIAdABpAGUAcwBbACcAQwBvAGQAZQAnAF0ALgBWAGEAbAB1AGUAOwAgAGkAZQB4ACAAJABlAHgAZQBjAA" nocase ascii wide
                        $string13 = "'Win32_Backdoor'" nocase ascii wide

    condition:
        any of them
}