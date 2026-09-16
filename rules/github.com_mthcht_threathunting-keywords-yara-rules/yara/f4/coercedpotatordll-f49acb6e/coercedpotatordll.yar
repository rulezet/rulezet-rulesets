rule CoercedPotatoRDLL
{
    meta:
        description = "Detection patterns for the tool 'CoercedPotatoRDLL' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CoercedPotatoRDLL"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sCoercedPotato\.cpp/ nocase ascii wide
                        $string2 = /\sspawn\sC\:\\Windows\\Temp\\beacon\.exe/ nocase ascii wide
                        $string3 = /\sspawn\sC\:\\Windows\\Temp\\loader\.exe/ nocase ascii wide
                        $string4 = /\/CoercedPotato\.cpp/ nocase ascii wide
                        $string5 = /\/CoercedPotatoRDLL\.git/ nocase ascii wide
                        $string6 = /\[\+\]\sExploit\sworked.{0,1000}\sit\sshould\sexecute\syour\scommand\sas\sSYSTEM\!/ nocase ascii wide
                        $string7 = /\\\\\.\\pipe\\coerced\\pipe\\spoolss/ nocase ascii wide
                        $string8 = /\\127\.0\.0\.1\/pipe\/coerced/ nocase ascii wide
                        $string9 = /\\CoercedPotato\.cpp/ nocase ascii wide
                        $string10 = "337ED7BE-969A-40C4-A356-BE99561F4633" nocase ascii wide
                        $string11 = "CoercedPotato spawn " nocase ascii wide
                        $string12 = /CoercedPotato\.exe/ nocase ascii wide
                        $string13 = "CoercedPotatoRDLL-main" nocase ascii wide
                        $string14 = "CoercePotato coerce" nocase ascii wide
                        $string15 = /dist\/coercedpotato\.cna/ nocase ascii wide
                        $string16 = /ReflectiveDLLInjection\.h/ nocase ascii wide
                        $string17 = /ReflectiveLoader\.cpp/ nocase ascii wide
                        $string18 = "sokaRepo/CoercedPotatoRDLL" nocase ascii wide
                        $string19 = "Spawn CoercedPotato as a Reflective DLL" nocase ascii wide

    condition:
        any of them
}