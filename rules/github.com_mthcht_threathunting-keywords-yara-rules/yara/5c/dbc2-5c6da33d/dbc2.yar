rule DBC2
{
    meta:
        description = "Detection patterns for the tool 'DBC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DBC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-DestHost\s.{0,100}\s\-DestPort\s5555\s\-UseDefaultProxy/ nocase ascii wide
                        $string2 = "/dbc2Loader" nocase ascii wide
                        $string3 = /\/MailRaider\.ps1/ nocase ascii wide
                        $string4 = /\/oneliner\.tpl/ nocase ascii wide
                        $string5 = /\/oneliner2\.tpl/ nocase ascii wide
                        $string6 = /\/persist\.tpl/ nocase ascii wide
                        $string7 = /\/posh\.tpl/ nocase ascii wide
                        $string8 = "Arno0x/DBC2" nocase ascii wide
                        $string9 = /ConvertTo\-Shellcode\.ps1/ nocase ascii wide
                        $string10 = /DBC2\.git/ nocase ascii wide
                        $string11 = /dbc2_agent\.cs/ nocase ascii wide
                        $string12 = /dbc2_agent\.exe/ nocase ascii wide
                        $string13 = /dbc2Loader\.dll/ nocase ascii wide
                        $string14 = /dbc2Loader\.exe/ nocase ascii wide
                        $string15 = /dbc2Loader\.tpl/ nocase ascii wide
                        $string16 = /dbc2LoaderWrapperCLR\./ nocase ascii wide
                        $string17 = /dbc2LoaderWrapperCLR_x64\.dll/ nocase ascii wide
                        $string18 = /dbc2LoaderWrapperCLR_x86\.dll/ nocase ascii wide
                        $string19 = /DBC2\-master\.zip/ nocase ascii wide
                        $string20 = /dnscat2\.ps1/ nocase ascii wide
                        $string21 = /dropboxC2\.py/ nocase ascii wide
                        $string22 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
                        $string23 = /Invoke\-NTLMAuth\.ps1/ nocase ascii wide
                        $string24 = "Invoke-PowerDump" nocase ascii wide
                        $string25 = "Invoke-ReflectivePEInjection" nocase ascii wide
                        $string26 = "Invoke-SendMail -Targets" nocase ascii wide
                        $string27 = "Invoke-SendReverseShell" nocase ascii wide
                        $string28 = "Invoke-Shellcode -Shellcode" nocase ascii wide
                        $string29 = /powercat\s\-c\s.{0,100}\s\-p\s/ nocase ascii wide
                        $string30 = "powercat -l -p 4444" nocase ascii wide
                        $string31 = /Powercat\.ps1/ nocase ascii wide
                        $string32 = /powershell\.exe\s\-NoP\s\-sta\s\-NonI\s\-W\sHidden\s\-Command\s.{0,100}Action\s\=\sNew\-ScheduledTaskAction\s\-Execute\s/ nocase ascii wide
                        $string33 = /PowerView\.ps1/ nocase ascii wide
                        $string34 = /regsvr32\.exe\s\/s\s\/n\s\/u\s\/i\:\s.{0,100}\sscrobj\.dll/ nocase ascii wide
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