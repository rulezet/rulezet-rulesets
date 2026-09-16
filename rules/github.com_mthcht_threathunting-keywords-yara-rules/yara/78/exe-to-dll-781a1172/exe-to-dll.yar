rule exe_to_dll
{
    meta:
        description = "Detection patterns for the tool 'exe_to_dll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "exe_to_dll"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/exe_to_dll\.git/ nocase ascii wide
                        $string2 = /\/exe_to_dll\.git/ nocase ascii wide
                        $string3 = /\/pe2shc\.exe/ nocase ascii wide
                        $string4 = /\\exe_to_dll\\/ nocase ascii wide
                        $string5 = /exe_to_dll\.exe/ nocase ascii wide
                        $string6 = /exe_to_dll\.exe/ nocase ascii wide
                        $string7 = /exe_to_dll_.{0,1000}\.zip/ nocase ascii wide
                        $string8 = /exe_to_dll_.{0,1000}_32bit\.zip/ nocase ascii wide
                        $string9 = /exe_to_dll_.{0,1000}_64bit\.zip/ nocase ascii wide
                        $string10 = "exe_to_dll-master" nocase ascii wide
                        $string11 = "exe_to_dll-master" nocase ascii wide
                        $string12 = "hasherezade/exe_to_dll" nocase ascii wide
                        $string13 = "hasherezade/exe_to_dll" nocase ascii wide

    condition:
        any of them
}