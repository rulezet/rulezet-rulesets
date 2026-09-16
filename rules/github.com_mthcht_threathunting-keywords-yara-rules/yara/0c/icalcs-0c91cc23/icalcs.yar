rule icalcs
{
    meta:
        description = "Detection patterns for the tool 'icalcs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icalcs"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /icacls\s\\"C\:\\windows\\system32\\config\\SAM\\"\s\/grant/ nocase ascii wide
                        $string2 = /icacls\s.{0,1000}\(x86\)\\360\\"\s.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string3 = /icacls\s.{0,1000}\\360safe.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string4 = /icacls\s.{0,1000}\\AVAST\sSoftware.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string5 = /icacls\s.{0,1000}\\AVG\\".{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string6 = /icacls\s.{0,1000}\\Avira.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string7 = /icacls\s.{0,1000}\\Cezurity.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string8 = /icacls\s.{0,1000}\\COMODO.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string9 = /icacls\s.{0,1000}\\Doctor\sWeb.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string10 = /icacls\s.{0,1000}\\Enigma\sSoftware\sGroup.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string11 = /icacls\s.{0,1000}\\ESET.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string12 = /icacls\s.{0,1000}\\GRIZZLY\sAntivirus.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string13 = /icacls\s.{0,1000}\\grizzly.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string14 = /icacls\s.{0,1000}\\Kaspersky\sLab.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string15 = /icacls\s.{0,1000}\\Malwarebytes.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string16 = /icacls\s.{0,1000}\\Malwarebytes.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string17 = /icacls\s.{0,1000}\\McAfee.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string18 = /icacls\s.{0,1000}\\Norton.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string19 = /icacls\s.{0,1000}\\Panda\sSecurity.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string20 = /icacls\s.{0,1000}\\SpyHunter.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string21 = /icacls\s.{0,1000}\\SpyHunter.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string22 = /icacls\sc\:\\windows\\system32\\sethc\.exe\s/ nocase ascii wide
                        $string23 = /icacls.{0,1000}\s\/grant\sEveryone\:F\s\/T\s\/C\s\/Q/ nocase ascii wide
                        $string24 = /icacls\.exe\sC\:\\Windows\\System32\\amsi\.dll\s\/grant\sadministrators\:F/ nocase ascii wide

    condition:
        any of them
}