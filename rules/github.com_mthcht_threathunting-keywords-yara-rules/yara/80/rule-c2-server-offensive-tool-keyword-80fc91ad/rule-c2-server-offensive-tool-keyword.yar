rule rule_C2_Server_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'C2_Server' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2_Server"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_C2_Server_offensive_tool_keyword = /\srev_shell\.py/ nocase ascii wide
                        $string2_C2_Server_offensive_tool_keyword = /\/C2_Server\.git/ nocase ascii wide
                        $string3_C2_Server_offensive_tool_keyword = /\/rev_shell\.py/ nocase ascii wide
                        $string4_C2_Server_offensive_tool_keyword = /\[\+\]\sBack\sto\sC\&C\sConsole/ nocase ascii wide
                        $string5_C2_Server_offensive_tool_keyword = /\[\+\]\sKeylogger\sstarted/ nocase ascii wide
                        $string6_C2_Server_offensive_tool_keyword = /\[\+\]\sKeylogger\sstopped/ nocase ascii wide
                        $string7_C2_Server_offensive_tool_keyword = /\\\srev_shell\.py/ nocase ascii wide
                        $string8_C2_Server_offensive_tool_keyword = /\\Chrome_pass\.db/ nocase ascii wide
                        $string9_C2_Server_offensive_tool_keyword = /192\.168\.0\.110\:1234/ nocase ascii wide
                        $string10_C2_Server_offensive_tool_keyword = "C&C => " nocase ascii wide
                        $string11_C2_Server_offensive_tool_keyword = "C2_Server-main" nocase ascii wide
                        $string12_C2_Server_offensive_tool_keyword = /chrome_creds\.txt/ nocase ascii wide
                        $string13_C2_Server_offensive_tool_keyword = /Invoke\-WebRequest\shttps\:\/\/tinyurl\.com\// nocase ascii wide
                        $string14_C2_Server_offensive_tool_keyword = "keylog_dump" nocase ascii wide
                        $string15_C2_Server_offensive_tool_keyword = "keylog_off" nocase ascii wide
                        $string16_C2_Server_offensive_tool_keyword = "keylog_on" nocase ascii wide
                        $string17_C2_Server_offensive_tool_keyword = /lnx_keylogger\.py/ nocase ascii wide
                        $string18_C2_Server_offensive_tool_keyword = "reveng007/C2_Server" nocase ascii wide
                        $string19_C2_Server_offensive_tool_keyword = "spoof_wani" nocase ascii wide
                        $string20_C2_Server_offensive_tool_keyword = "spoof_wlan_creds" nocase ascii wide
                        $string21_C2_Server_offensive_tool_keyword = /win_chrome_password_extractor\.py/ nocase ascii wide
                        $string22_C2_Server_offensive_tool_keyword = /win_keylogger\.py/ nocase ascii wide
                        $string23_C2_Server_offensive_tool_keyword = /win_wlan_passwd_and_wanip_extractor\.py/ nocase ascii wide
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