rule rule_Lsassx_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Lsassx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lsassx"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Lsassx_offensive_tool_keyword = /\sLsassx\.ps1/ nocase ascii wide
                        $string2_Lsassx_offensive_tool_keyword = /\sLsassx\-OBF\.ps1/ nocase ascii wide
                        $string3_Lsassx_offensive_tool_keyword = "# Using reflection to dump LSASS in-memory with stealth" nocase ascii wide
                        $string4_Lsassx_offensive_tool_keyword = /\/Lsassx\.git/ nocase ascii wide
                        $string5_Lsassx_offensive_tool_keyword = /\/Lsassx\.ps1/ nocase ascii wide
                        $string6_Lsassx_offensive_tool_keyword = /\/Lsassx\-OBF\.ps1/ nocase ascii wide
                        $string7_Lsassx_offensive_tool_keyword = /\[\!\]\sIn\-memory\sLSASS\sdump\smethod\sfailed\:\s/ nocase ascii wide
                        $string8_Lsassx_offensive_tool_keyword = /\[\!\]\sLSASS\sdump\sfailed\s/ nocase ascii wide
                        $string9_Lsassx_offensive_tool_keyword = /\[\+\]\sLSASS\sdump\screated\ssuccessfully\./ nocase ascii wide
                        $string10_Lsassx_offensive_tool_keyword = /\[Text\.Encoding\]\:\:Unicode\.GetString\(\[Convert\]\:\:FromBase64String\(\'bABzAGEAcwBzAA\=\=/ nocase ascii wide
                        $string11_Lsassx_offensive_tool_keyword = /\\Lsassx\.ps1/ nocase ascii wide
                        $string12_Lsassx_offensive_tool_keyword = /\\Lsassx\-main/ nocase ascii wide
                        $string13_Lsassx_offensive_tool_keyword = /\\Lsassx\-OBF\.ps1/ nocase ascii wide
                        $string14_Lsassx_offensive_tool_keyword = /\]\sAttempting\sstealthy\sLSASS\sdump/ nocase ascii wide
                        $string15_Lsassx_offensive_tool_keyword = "a60a04cda101deaab5c2aa8b25c715fffc7a4f3e9813fa6d53a5b25dd4126fe2" nocase ascii wide
                        $string16_Lsassx_offensive_tool_keyword = "af6d177df40fcf715f752557c9fd2483a5e194c1c468625a76a4862632db5cb6" nocase ascii wide
                        $string17_Lsassx_offensive_tool_keyword = /C\:\\Users\\Public\\backup\.enc/ nocase ascii wide
                        $string18_Lsassx_offensive_tool_keyword = /C\:\\Users\\Public\\syslog\.dat/ nocase ascii wide
                        $string19_Lsassx_offensive_tool_keyword = /C\:\\Users\\Public\\syslog\.zip/ nocase ascii wide
                        $string20_Lsassx_offensive_tool_keyword = /decoded_lsass\.dmp/ nocase ascii wide
                        $string21_Lsassx_offensive_tool_keyword = "IAAgACAAIAB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQA7AA0ACgAgACAAIAAgAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzADsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABjAGwAYQBzAHMAIABMAFMAQQBTAFMARAB1AG0AcAA" nocase ascii wide
                        $string22_Lsassx_offensive_tool_keyword = "public class LSASSDump" nocase ascii wide
                        $string23_Lsassx_offensive_tool_keyword = "QwA6AFwAVQBzAGUAcgBzAFwAUAB1AGIAbABpAGMAXABiAGEAYwBrAHUAcAAuAGUAbgBjAA==" nocase ascii wide
                        $string24_Lsassx_offensive_tool_keyword = "QwA6AFwAVQBzAGUAcgBzAFwAUAB1AGIAbABpAGMAXABzAHkAcwBsAG8AZwAuAGQAYQB0AA==" nocase ascii wide
                        $string25_Lsassx_offensive_tool_keyword = "QwA6AFwAVQBzAGUAcgBzAFwAUAB1AGIAbABpAGMAXABzAHkAcwBsAG8AZwAuAHoAaQBwAA==" nocase ascii wide
                        $string26_Lsassx_offensive_tool_keyword = "WwAhAF0AIABJAG4ALQBtAGUAbQBvAHIAeQAgAEwAUwBBAFMAUwAgAGQAdQBtAHAAIABtAGUAdABoAG8AZAAgAGYAYQBpAGwAZQBkADoAIAAkAF8A" nocase ascii wide
                        $string27_Lsassx_offensive_tool_keyword = "WwAhAF0AIABMAFMAQQBTAFMAIABkAHUAbQBwACAAZgBhAGkAbABlAGQAIAB1AHMAaQBuAGcAIABzAHQAZQBhAGwAdABoACAAbQBlAHQAaABvAGQALgA=" nocase ascii wide
                        $string28_Lsassx_offensive_tool_keyword = "WwAhAF0AIABMAFMAQQBTAFMAIABkAHUAbQBwACAAZgBhAGkAbABlAGQALgAgAEUAeABpAHQAaQBuAGcAIABzAGMAcgBpAHAAdAAuAA==" nocase ascii wide
                        $string29_Lsassx_offensive_tool_keyword = "WwAqAF0AIABBAHQAdABlAG0AcAB0AGkAbgBnACAAcwB0AGUAYQBsAHQAaAB5ACAATABTAEEAUwBTACAAZAB1AG0AcAAgAHUAcwBpAG4AZwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAByAGUAZgBsAGUAYwB0AGkAbwBuAC4ALgAuAA==" nocase ascii wide
                        $string30_Lsassx_offensive_tool_keyword = "WwAqAF0AIABEAG8AbgBlAC4AIABDAGgAZQBjAGsAIAAkAHsAXwAvAD0AXABfAC8AXABfAF8ALwBcAF8ALwA9AFwALwA9AH0AIABmAG8AcgAgAHQAaABlACAAZgBpAG4AYQBsACAAYQByAGMAaABpAHYAZQAgAGkAZgAgAHMAdQBjAGMAZQBzAHMAZgB1AGwALgA=" nocase ascii wide
                        $string31_Lsassx_offensive_tool_keyword = "WwArAF0AIABDAG8AbQBwAHIAZQBzAHMAaQBvAG4AIABjAG8AbQBwAGwAZQB0AGUAZAA6ACAAJAB7AF8ALwA9AFwAXwAvAFwAXwBfAC8AXABfAC8APQBcAC8APQB9AA==" nocase ascii wide
                        $string32_Lsassx_offensive_tool_keyword = "WwArAF0AIABEAHUAbQBwACAAZgBpAGwAZQAgAGUAbgBjAHIAeQBwAHQAZQBkACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkALgA=" nocase ascii wide
                        $string33_Lsassx_offensive_tool_keyword = "WwArAF0AIABMAFMAQQBTAFMAIABkAHUAbQBwACAAYwByAGUAYQB0AGUAZAAgAHMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5AC4A" nocase ascii wide
                        $string34_Lsassx_offensive_tool_keyword = "yehia-mamdouh/Lsassx" nocase ascii wide
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