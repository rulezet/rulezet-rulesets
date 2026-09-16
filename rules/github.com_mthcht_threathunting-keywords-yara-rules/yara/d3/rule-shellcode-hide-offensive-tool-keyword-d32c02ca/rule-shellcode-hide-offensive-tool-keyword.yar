rule rule_Shellcode_Hide_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Shellcode-Hide' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shellcode-Hide"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Shellcode_Hide_offensive_tool_keyword = /\/IPfuscation\.cpp/ nocase ascii wide
                        $string2_Shellcode_Hide_offensive_tool_keyword = /\/IPfuscation\.exe/ nocase ascii wide
                        $string3_Shellcode_Hide_offensive_tool_keyword = /\/Shellcode\-Hide\.git/ nocase ascii wide
                        $string4_Shellcode_Hide_offensive_tool_keyword = /\/SimpleLoader\.cpp/ nocase ascii wide
                        $string5_Shellcode_Hide_offensive_tool_keyword = /\/SimpleLoader\.exe/ nocase ascii wide
                        $string6_Shellcode_Hide_offensive_tool_keyword = /\\CustomEncoding\.cpp/ nocase ascii wide
                        $string7_Shellcode_Hide_offensive_tool_keyword = /\\IPfuscation\.cpp/ nocase ascii wide
                        $string8_Shellcode_Hide_offensive_tool_keyword = /\\IPfuscation\.exe/ nocase ascii wide
                        $string9_Shellcode_Hide_offensive_tool_keyword = /\\SimpleLoader\.cpp/ nocase ascii wide
                        $string10_Shellcode_Hide_offensive_tool_keyword = /\\SimpleLoader\.exe/ nocase ascii wide
                        $string11_Shellcode_Hide_offensive_tool_keyword = "11385CC1-54B7-4968-9052-DF8BB1961F1E" nocase ascii wide
                        $string12_Shellcode_Hide_offensive_tool_keyword = "1617117C-0E94-4E6A-922C-836D616EC1F5" nocase ascii wide
                        $string13_Shellcode_Hide_offensive_tool_keyword = "497CA37F-506C-46CD-9B8D-F9BB0DA34B95" nocase ascii wide
                        $string14_Shellcode_Hide_offensive_tool_keyword = "70527328-DCEC-4BA7-9958-B5BC3E48CE99" nocase ascii wide
                        $string15_Shellcode_Hide_offensive_tool_keyword = "847D29FF-8BBC-4068-8BE1-D84B1089B3C0" nocase ascii wide
                        $string16_Shellcode_Hide_offensive_tool_keyword = "9AA32BBF-90F3-4CE6-B210-CBCDB85052B0" nocase ascii wide
                        $string17_Shellcode_Hide_offensive_tool_keyword = "B651A53C-FAE6-482E-A590-CA3B48B7F384" nocase ascii wide
                        $string18_Shellcode_Hide_offensive_tool_keyword = "E991E6A7-31EA-42E3-A471-90F0090E3AFD" nocase ascii wide
                        $string19_Shellcode_Hide_offensive_tool_keyword = /FilelessShellcode\.cpp/ nocase ascii wide
                        $string20_Shellcode_Hide_offensive_tool_keyword = /FilelessShellcode\.exe/ nocase ascii wide
                        $string21_Shellcode_Hide_offensive_tool_keyword = /FilelessShellcode\.sln/ nocase ascii wide
                        $string22_Shellcode_Hide_offensive_tool_keyword = /FilelessShellcode\.vcxproj/ nocase ascii wide
                        $string23_Shellcode_Hide_offensive_tool_keyword = /IPfuscation\.sln/ nocase ascii wide
                        $string24_Shellcode_Hide_offensive_tool_keyword = /IPfuscation\.vcxproj/ nocase ascii wide
                        $string25_Shellcode_Hide_offensive_tool_keyword = /MACshellcode\.cpp/ nocase ascii wide
                        $string26_Shellcode_Hide_offensive_tool_keyword = /MACshellcode\.exe/ nocase ascii wide
                        $string27_Shellcode_Hide_offensive_tool_keyword = /MACshellcode\.sln/ nocase ascii wide
                        $string28_Shellcode_Hide_offensive_tool_keyword = /MACshellcode\.vcxproj/ nocase ascii wide
                        $string29_Shellcode_Hide_offensive_tool_keyword = "Shellcode-Hide-main" nocase ascii wide
                        $string30_Shellcode_Hide_offensive_tool_keyword = "TheD1rkMtr/Shellcode-Hide" nocase ascii wide
                        $string31_Shellcode_Hide_offensive_tool_keyword = /WinhttpShellcode\.cpp/ nocase ascii wide
                        $string32_Shellcode_Hide_offensive_tool_keyword = /WinhttpShellcode\.exe/ nocase ascii wide
                        $string33_Shellcode_Hide_offensive_tool_keyword = /WinhttpShellcode\.sln/ nocase ascii wide
                        $string34_Shellcode_Hide_offensive_tool_keyword = /WinhttpShellcode\.vcxproj/ nocase ascii wide
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