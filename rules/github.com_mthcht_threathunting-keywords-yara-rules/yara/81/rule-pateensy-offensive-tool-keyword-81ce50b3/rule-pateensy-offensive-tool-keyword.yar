rule rule_Pateensy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Pateensy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pateensy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Pateensy_offensive_tool_keyword = /\/paensy\.cpp/ nocase ascii wide
                        $string2_Pateensy_offensive_tool_keyword = /BadUSB_AddAdmin\.ino/ nocase ascii wide
                        $string3_Pateensy_offensive_tool_keyword = /BadUSB_DownloadExecute\.ino/ nocase ascii wide
                        $string4_Pateensy_offensive_tool_keyword = /BadUSB_FacebookPost\.ino/ nocase ascii wide
                        $string5_Pateensy_offensive_tool_keyword = /BadUSB_HideWindow\.ino/ nocase ascii wide
                        $string6_Pateensy_offensive_tool_keyword = /BadUSB_LockYourComputer\.ino/ nocase ascii wide
                        $string7_Pateensy_offensive_tool_keyword = /Bye_Explorer\.ino/ nocase ascii wide
                        $string8_Pateensy_offensive_tool_keyword = "Pateensy/PaensyLib/" nocase ascii wide
                        $string9_Pateensy_offensive_tool_keyword = /powershell\-admin\-download\-execute\.ino/ nocase ascii wide
                        $string10_Pateensy_offensive_tool_keyword = "screetsec/Pateensy" nocase ascii wide
                        $string11_Pateensy_offensive_tool_keyword = /Teensypreter\.ino/ nocase ascii wide
                        $string12_Pateensy_offensive_tool_keyword = /WiFi_Hacker\.ino/ nocase ascii wide
                        $string13_Pateensy_offensive_tool_keyword = /Windows7\-BypassLogon\-Screen\.ino/ nocase ascii wide
                        $string14_Pateensy_offensive_tool_keyword = /windows\-forkbomb\.ino/ nocase ascii wide
                        $string15_Pateensy_offensive_tool_keyword = /You_spin_me__round\.ino/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}