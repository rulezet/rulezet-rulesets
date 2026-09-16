rule rule_CoercedPotatoRDLL_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CoercedPotatoRDLL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CoercedPotatoRDLL"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CoercedPotatoRDLL_offensive_tool_keyword = /\sCoercedPotato\.cpp/ nocase ascii wide
                        $string2_CoercedPotatoRDLL_offensive_tool_keyword = /\sspawn\sC\:\\Windows\\Temp\\beacon\.exe/ nocase ascii wide
                        $string3_CoercedPotatoRDLL_offensive_tool_keyword = /\sspawn\sC\:\\Windows\\Temp\\loader\.exe/ nocase ascii wide
                        $string4_CoercedPotatoRDLL_offensive_tool_keyword = /\/CoercedPotato\.cpp/ nocase ascii wide
                        $string5_CoercedPotatoRDLL_offensive_tool_keyword = /\/CoercedPotatoRDLL\.git/ nocase ascii wide
                        $string6_CoercedPotatoRDLL_offensive_tool_keyword = /\[\+\]\sExploit\sworked.{0,1000}\sit\sshould\sexecute\syour\scommand\sas\sSYSTEM\!/ nocase ascii wide
                        $string7_CoercedPotatoRDLL_offensive_tool_keyword = /\\\\\.\\pipe\\coerced\\pipe\\spoolss/ nocase ascii wide
                        $string8_CoercedPotatoRDLL_offensive_tool_keyword = /\\127\.0\.0\.1\/pipe\/coerced/ nocase ascii wide
                        $string9_CoercedPotatoRDLL_offensive_tool_keyword = /\\CoercedPotato\.cpp/ nocase ascii wide
                        $string10_CoercedPotatoRDLL_offensive_tool_keyword = "337ED7BE-969A-40C4-A356-BE99561F4633" nocase ascii wide
                        $string11_CoercedPotatoRDLL_offensive_tool_keyword = "CoercedPotato spawn " nocase ascii wide
                        $string12_CoercedPotatoRDLL_offensive_tool_keyword = /CoercedPotato\.exe/ nocase ascii wide
                        $string13_CoercedPotatoRDLL_offensive_tool_keyword = "CoercedPotatoRDLL-main" nocase ascii wide
                        $string14_CoercedPotatoRDLL_offensive_tool_keyword = "CoercePotato coerce" nocase ascii wide
                        $string15_CoercedPotatoRDLL_offensive_tool_keyword = /dist\/coercedpotato\.cna/ nocase ascii wide
                        $string16_CoercedPotatoRDLL_offensive_tool_keyword = /ReflectiveDLLInjection\.h/ nocase ascii wide
                        $string17_CoercedPotatoRDLL_offensive_tool_keyword = /ReflectiveLoader\.cpp/ nocase ascii wide
                        $string18_CoercedPotatoRDLL_offensive_tool_keyword = "sokaRepo/CoercedPotatoRDLL" nocase ascii wide
                        $string19_CoercedPotatoRDLL_offensive_tool_keyword = "Spawn CoercedPotato as a Reflective DLL" nocase ascii wide

    condition:
        any of them
}