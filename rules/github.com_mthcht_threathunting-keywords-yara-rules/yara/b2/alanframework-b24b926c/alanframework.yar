rule AlanFramework
{
    meta:
        description = "Detection patterns for the tool 'AlanFramework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AlanFramework"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/alan\.log/
                        $string2 = /\/Alan\.v.{0,100}\.zip/ nocase ascii wide
                        $string3 = /\\agent_exe\.exe/ nocase ascii wide
                        $string4 = /\\alan\.log/ nocase ascii wide
                        $string5 = /\\Alan\.v.{0,100}\.zip/ nocase ascii wide
                        $string6 = /\\asm\\x64\\alter_pe_sections/ nocase ascii wide
                        $string7 = /\\asm\\x86\\alter_pe_sections/ nocase ascii wide
                        $string8 = /\\ES\.Alan\.Core/ nocase ascii wide
                        $string9 = /agent\/cmd_download_files\./ nocase ascii wide
                        $string10 = /agent\/cmd_exec\./ nocase ascii wide
                        $string11 = /agent\/cmd_kill\./ nocase ascii wide
                        $string12 = /agent\/cmd_proxy\./ nocase ascii wide
                        $string13 = /agent\/cmd_run\.c/ nocase ascii wide
                        $string14 = /agent\/cmd_shell\./ nocase ascii wide
                        $string15 = /agent\/cmd_sleep\./ nocase ascii wide
                        $string16 = /agent\/cmd_sysinfo\.c/ nocase ascii wide
                        $string17 = /agent\/cmd_upload_files\./ nocase ascii wide
                        $string18 = /agent\\cmd_download_files\./ nocase ascii wide
                        $string19 = /agent\\cmd_exec\./ nocase ascii wide
                        $string20 = /agent\\cmd_kill\./ nocase ascii wide
                        $string21 = /agent\\cmd_proxy\./ nocase ascii wide
                        $string22 = /agent\\cmd_run\.c/ nocase ascii wide
                        $string23 = /agent\\cmd_shell\./ nocase ascii wide
                        $string24 = /agent\\cmd_sleep\./ nocase ascii wide
                        $string25 = /agent\\cmd_sysinfo\.c/ nocase ascii wide
                        $string26 = /agent\\cmd_upload_files\./ nocase ascii wide
                        $string27 = /agent_dll\.dll/ nocase ascii wide
                        $string28 = /AlanFramework\.git/ nocase ascii wide
                        $string29 = /c\:\\agent\.exe/ nocase ascii wide
                        $string30 = /dotnet\s\.\/Server\.dll/
                        $string31 = /DownloadString.{0,100}https\:\/\/checkip\.amazonaws\.com/ nocase ascii wide
                        $string32 = /dump_lsass\.js/ nocase ascii wide
                        $string33 = /dump_process\(.{0,100}lsass\.exe.{0,100}\)/ nocase ascii wide
                        $string34 = "enkomio/AlanFramework" nocase ascii wide
                        $string35 = /ES\.Alan\.Core\// nocase ascii wide
                        $string36 = /http.{0,100}\:\/\/127\.0\.0\.1\:4433/ nocase ascii wide
                        $string37 = /http.{0,100}\:\/\/127\.0\.0\.1\:5556/ nocase ascii wide
                        $string38 = /http.{0,100}\:\/\/localhost\:4433/ nocase ascii wide
                        $string39 = /http.{0,100}\:\/\/localhost\:5556/ nocase ascii wide
                        $string40 = /pe_packer\/dll_main\.c/ nocase ascii wide
                        $string41 = /pe_packer\/exe_main\.c/ nocase ascii wide
                        $string42 = /pe_packer\/main\.c/ nocase ascii wide
                        $string43 = /pe_packer\\dll_main\.c/ nocase ascii wide
                        $string44 = /pe_packer\\exe_main\.c/ nocase ascii wide
                        $string45 = /pe_packer\\main\.c/ nocase ascii wide
                        $string46 = /pe_packer_exe\.exe/ nocase ascii wide
                        $string47 = /powershell_command_x64\.ps1/ nocase ascii wide
                        $string48 = /powershell_command_x86\.ps1/ nocase ascii wide
                        $string49 = /socks5_exe\.exe/ nocase ascii wide
                        $string50 = /stagerx64\.bin/ nocase ascii wide
                        $string51 = "test_nanodump_exe" nocase ascii wide
                        $string52 = "windows_agent/asm/x64/alter_pe_sections" nocase ascii wide
                        $string53 = "windows_agent/asm/x86/alter_pe_sections" nocase ascii wide
                        $string54 = /windows_agent\/dll_main\./ nocase ascii wide
                        $string55 = /windows_agent\/exe_main\./ nocase ascii wide
                        $string56 = /windows_agent\/win_.{0,100}\.c/ nocase ascii wide
                        $string57 = /windows_agent\/win_named_pipe\./ nocase ascii wide
                        $string58 = /windows_agent\/win_shell\./ nocase ascii wide
                        $string59 = /windows_console_interceptor.{0,100}dll_main\.c/ nocase ascii wide
                        $string60 = /windows_console_interceptor.{0,100}exe_main\.c/ nocase ascii wide
                        $string61 = /windows_console_interceptor.{0,100}interceptor\./ nocase ascii wide
                        $string62 = /x64PELoader\/.{0,100}\.exe/ nocase ascii wide
                        $string63 = /x86PELoader\/.{0,100}\.exe/ nocase ascii wide
                        $string64 = "x86PELoader/test_agent_dll" nocase ascii wide
                        $string65 = "x86PELoader/test_agent_exe" nocase ascii wide
                        $string66 = "x86PELoader/test_proxy_dll" nocase ascii wide
                        $string67 = "x86PELoader/test_proxy_exe" nocase ascii wide
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