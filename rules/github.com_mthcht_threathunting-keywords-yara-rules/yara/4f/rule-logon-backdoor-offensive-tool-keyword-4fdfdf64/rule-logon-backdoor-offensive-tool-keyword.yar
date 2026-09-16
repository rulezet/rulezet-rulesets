rule rule_logon_backdoor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'logon_backdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "logon_backdoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_logon_backdoor_offensive_tool_keyword = /\/backdoor\.bat/ nocase ascii wide
                        $string2_logon_backdoor_offensive_tool_keyword = /\/backdoor\.exe/ nocase ascii wide
                        $string3_logon_backdoor_offensive_tool_keyword = /\/logon_backdoor\.git/ nocase ascii wide
                        $string4_logon_backdoor_offensive_tool_keyword = /\[\sbackdoor\s\-\sDebug\s\]/ nocase ascii wide
                        $string5_logon_backdoor_offensive_tool_keyword = /\\backdoor\.bat/ nocase ascii wide
                        $string6_logon_backdoor_offensive_tool_keyword = /\\backdoor\.exe/ nocase ascii wide
                        $string7_logon_backdoor_offensive_tool_keyword = /\\backdoor\\backdoor\.mk/ nocase ascii wide
                        $string8_logon_backdoor_offensive_tool_keyword = /\\backdoor\\backdoor\.project/ nocase ascii wide
                        $string9_logon_backdoor_offensive_tool_keyword = /\\backdoor_new\.bat/ nocase ascii wide
                        $string10_logon_backdoor_offensive_tool_keyword = /\\logon_backdoor\\/ nocase ascii wide
                        $string11_logon_backdoor_offensive_tool_keyword = /\\logon_backdoor\-master/ nocase ascii wide
                        $string12_logon_backdoor_offensive_tool_keyword = /\\oem\\Desktop\\backdoor/ nocase ascii wide
                        $string13_logon_backdoor_offensive_tool_keyword = /\'1\.\sSet\sthe\sbackdoor\'/ nocase ascii wide
                        $string14_logon_backdoor_offensive_tool_keyword = "59a64374f430585117c385edce4ac8ff536cb2710a0037384f9f869601752af1" nocase ascii wide
                        $string15_logon_backdoor_offensive_tool_keyword = "6e0055eba5cf62d9ac7b129e55d3f230fef2dd432d88313ae08d85d9ff5c2329" nocase ascii wide
                        $string16_logon_backdoor_offensive_tool_keyword = "a93f02549ee6f5a59d0472755b8719284f64e0ac451906a42d8eb9f5738add67" nocase ascii wide
                        $string17_logon_backdoor_offensive_tool_keyword = "Backdoor has been set up successfully" nocase ascii wide
                        $string18_logon_backdoor_offensive_tool_keyword = /Backdoor\sis\salready\sremoved\s\:\)/ nocase ascii wide
                        $string19_logon_backdoor_offensive_tool_keyword = /Backdoor\sis\salready\sset\sup\s\;\)/ nocase ascii wide
                        $string20_logon_backdoor_offensive_tool_keyword = /REG\sDELETE\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe\\"/ nocase ascii wide
                        $string21_logon_backdoor_offensive_tool_keyword = "szymon1118/logon_backdoor" nocase ascii wide
                        $string22_logon_backdoor_offensive_tool_keyword = "title logon backdoor" nocase ascii wide
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