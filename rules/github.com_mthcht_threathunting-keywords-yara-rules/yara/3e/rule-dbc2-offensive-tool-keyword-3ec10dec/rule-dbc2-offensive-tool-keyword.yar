rule rule_DBC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DBC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DBC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DBC2_offensive_tool_keyword = /\s\-DestHost\s.{0,100}\s\-DestPort\s5555\s\-UseDefaultProxy/ nocase ascii wide
                        $string2_DBC2_offensive_tool_keyword = "/dbc2Loader" nocase ascii wide
                        $string3_DBC2_offensive_tool_keyword = /\/MailRaider\.ps1/ nocase ascii wide
                        $string4_DBC2_offensive_tool_keyword = /\/oneliner\.tpl/ nocase ascii wide
                        $string5_DBC2_offensive_tool_keyword = /\/oneliner2\.tpl/ nocase ascii wide
                        $string6_DBC2_offensive_tool_keyword = /\/persist\.tpl/ nocase ascii wide
                        $string7_DBC2_offensive_tool_keyword = /\/posh\.tpl/ nocase ascii wide
                        $string8_DBC2_offensive_tool_keyword = "Arno0x/DBC2" nocase ascii wide
                        $string9_DBC2_offensive_tool_keyword = /ConvertTo\-Shellcode\.ps1/ nocase ascii wide
                        $string10_DBC2_offensive_tool_keyword = /DBC2\.git/ nocase ascii wide
                        $string11_DBC2_offensive_tool_keyword = /dbc2_agent\.cs/ nocase ascii wide
                        $string12_DBC2_offensive_tool_keyword = /dbc2_agent\.exe/ nocase ascii wide
                        $string13_DBC2_offensive_tool_keyword = /dbc2Loader\.dll/ nocase ascii wide
                        $string14_DBC2_offensive_tool_keyword = /dbc2Loader\.exe/ nocase ascii wide
                        $string15_DBC2_offensive_tool_keyword = /dbc2Loader\.tpl/ nocase ascii wide
                        $string16_DBC2_offensive_tool_keyword = /dbc2LoaderWrapperCLR\./ nocase ascii wide
                        $string17_DBC2_offensive_tool_keyword = /dbc2LoaderWrapperCLR_x64\.dll/ nocase ascii wide
                        $string18_DBC2_offensive_tool_keyword = /dbc2LoaderWrapperCLR_x86\.dll/ nocase ascii wide
                        $string19_DBC2_offensive_tool_keyword = /DBC2\-master\.zip/ nocase ascii wide
                        $string20_DBC2_offensive_tool_keyword = /dnscat2\.ps1/ nocase ascii wide
                        $string21_DBC2_offensive_tool_keyword = /dropboxC2\.py/ nocase ascii wide
                        $string22_DBC2_offensive_tool_keyword = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
                        $string23_DBC2_offensive_tool_keyword = /Invoke\-NTLMAuth\.ps1/ nocase ascii wide
                        $string24_DBC2_offensive_tool_keyword = "Invoke-PowerDump" nocase ascii wide
                        $string25_DBC2_offensive_tool_keyword = "Invoke-ReflectivePEInjection" nocase ascii wide
                        $string26_DBC2_offensive_tool_keyword = "Invoke-SendMail -Targets" nocase ascii wide
                        $string27_DBC2_offensive_tool_keyword = "Invoke-SendReverseShell" nocase ascii wide
                        $string28_DBC2_offensive_tool_keyword = "Invoke-Shellcode -Shellcode" nocase ascii wide
                        $string29_DBC2_offensive_tool_keyword = /powercat\s\-c\s.{0,100}\s\-p\s/ nocase ascii wide
                        $string30_DBC2_offensive_tool_keyword = "powercat -l -p 4444" nocase ascii wide
                        $string31_DBC2_offensive_tool_keyword = /Powercat\.ps1/ nocase ascii wide
                        $string32_DBC2_offensive_tool_keyword = /powershell\.exe\s\-NoP\s\-sta\s\-NonI\s\-W\sHidden\s\-Command\s.{0,100}Action\s\=\sNew\-ScheduledTaskAction\s\-Execute\s/ nocase ascii wide
                        $string33_DBC2_offensive_tool_keyword = /PowerView\.ps1/ nocase ascii wide
                        $string34_DBC2_offensive_tool_keyword = /regsvr32\.exe\s\/s\s\/n\s\/u\s\/i\:\s.{0,100}\sscrobj\.dll/ nocase ascii wide
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