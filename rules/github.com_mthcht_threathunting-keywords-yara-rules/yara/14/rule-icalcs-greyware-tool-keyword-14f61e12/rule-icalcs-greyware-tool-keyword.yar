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
                        $string2_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\(x86\)\\360\\"\s.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string3_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\360safe.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string4_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\AVAST\sSoftware.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string5_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\AVG\\".{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string6_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\Avira.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string7_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\Cezurity.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string8_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\COMODO.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string9_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\Doctor\sWeb.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string10_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\Enigma\sSoftware\sGroup.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string11_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\ESET.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string12_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\GRIZZLY\sAntivirus.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string13_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\grizzly.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string14_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\Kaspersky\sLab.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string15_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\Malwarebytes.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string16_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\Malwarebytes.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string17_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\McAfee.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string18_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\Norton.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string19_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\Panda\sSecurity.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string20_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\SpyHunter.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string21_icalcs_greyware_tool_keyword = /icacls\s.{0,100}\\SpyHunter.{0,100}\s\/deny\s\%username\%\:\(OI\)\(CI\)\(F\)/ nocase ascii wide
                        $string22_icalcs_greyware_tool_keyword = /icacls\sc\:\\windows\\system32\\sethc\.exe\s/ nocase ascii wide
                        $string23_icalcs_greyware_tool_keyword = /icacls.{0,100}\s\/grant\sEveryone\:F\s\/T\s\/C\s\/Q/ nocase ascii wide
                        $string24_icalcs_greyware_tool_keyword = /icacls\.exe\sC\:\\Windows\\System32\\amsi\.dll\s\/grant\sadministrators\:F/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}