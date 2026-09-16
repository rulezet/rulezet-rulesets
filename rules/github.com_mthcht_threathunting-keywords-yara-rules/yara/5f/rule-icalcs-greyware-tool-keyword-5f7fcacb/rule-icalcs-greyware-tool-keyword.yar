rule rule_icalcs_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'icalcs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icalcs"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_icalcs_greyware_tool_keyword = /icacls\s\\"C\:\\windows\\system32\\config\\SAM\\"\s\/grant/ nocase ascii wide
                        $string2_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\(x86\)\\360\\"\s.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string3_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\360safe.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string4_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\AVAST\sSoftware.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string5_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\AVG\\".{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string6_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\Avira.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string7_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\Cezurity.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string8_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\COMODO.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string9_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\Doctor\sWeb.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string10_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\Enigma\sSoftware\sGroup.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string11_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\ESET.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string12_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\GRIZZLY\sAntivirus.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string13_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\grizzly.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string14_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\Kaspersky\sLab.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string15_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\Malwarebytes.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string16_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\Malwarebytes.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string17_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\McAfee.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string18_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\Norton.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string19_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\Panda\sSecurity.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string20_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\SpyHunter.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string21_icalcs_greyware_tool_keyword = /icacls\s.{0,1000}\\SpyHunter.{0,1000}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string22_icalcs_greyware_tool_keyword = /icacls\sc\:\\windows\\system32\\sethc\.exe\s/ nocase ascii wide
                        $string23_icalcs_greyware_tool_keyword = /icacls.{0,1000}\s\/grant\sEveryone\:F\s\/T\s\/C\s\/Q/ nocase ascii wide
                        $string24_icalcs_greyware_tool_keyword = /icacls\.exe\sC\:\\Windows\\System32\\amsi\.dll\s\/grant\sadministrators\:F/ nocase ascii wide

    condition:
        any of them
}