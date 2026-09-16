rule rule_AlanFramework_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AlanFramework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AlanFramework"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AlanFramework_offensive_tool_keyword = /\/alan\.log/
                        $string2_AlanFramework_offensive_tool_keyword = /\/Alan\.v.{0,100}\.zip/ nocase ascii wide
                        $string3_AlanFramework_offensive_tool_keyword = /\\agent_exe\.exe/ nocase ascii wide
                        $string4_AlanFramework_offensive_tool_keyword = /\\alan\.log/ nocase ascii wide
                        $string5_AlanFramework_offensive_tool_keyword = /\\Alan\.v.{0,100}\.zip/ nocase ascii wide
                        $string6_AlanFramework_offensive_tool_keyword = /\\asm\\x64\\alter_pe_sections/ nocase ascii wide
                        $string7_AlanFramework_offensive_tool_keyword = /\\asm\\x86\\alter_pe_sections/ nocase ascii wide
                        $string8_AlanFramework_offensive_tool_keyword = /\\ES\.Alan\.Core/ nocase ascii wide
                        $string9_AlanFramework_offensive_tool_keyword = /agent\/cmd_download_files\./ nocase ascii wide
                        $string10_AlanFramework_offensive_tool_keyword = /agent\/cmd_exec\./ nocase ascii wide
                        $string11_AlanFramework_offensive_tool_keyword = /agent\/cmd_kill\./ nocase ascii wide
                        $string12_AlanFramework_offensive_tool_keyword = /agent\/cmd_proxy\./ nocase ascii wide
                        $string13_AlanFramework_offensive_tool_keyword = /agent\/cmd_run\.c/ nocase ascii wide
                        $string14_AlanFramework_offensive_tool_keyword = /agent\/cmd_shell\./ nocase ascii wide
                        $string15_AlanFramework_offensive_tool_keyword = /agent\/cmd_sleep\./ nocase ascii wide
                        $string16_AlanFramework_offensive_tool_keyword = /agent\/cmd_sysinfo\.c/ nocase ascii wide
                        $string17_AlanFramework_offensive_tool_keyword = /agent\/cmd_upload_files\./ nocase ascii wide
                        $string18_AlanFramework_offensive_tool_keyword = /agent\\cmd_download_files\./ nocase ascii wide
                        $string19_AlanFramework_offensive_tool_keyword = /agent\\cmd_exec\./ nocase ascii wide
                        $string20_AlanFramework_offensive_tool_keyword = /agent\\cmd_kill\./ nocase ascii wide
                        $string21_AlanFramework_offensive_tool_keyword = /agent\\cmd_proxy\./ nocase ascii wide
                        $string22_AlanFramework_offensive_tool_keyword = /agent\\cmd_run\.c/ nocase ascii wide
                        $string23_AlanFramework_offensive_tool_keyword = /agent\\cmd_shell\./ nocase ascii wide
                        $string24_AlanFramework_offensive_tool_keyword = /agent\\cmd_sleep\./ nocase ascii wide
                        $string25_AlanFramework_offensive_tool_keyword = /agent\\cmd_sysinfo\.c/ nocase ascii wide
                        $string26_AlanFramework_offensive_tool_keyword = /agent\\cmd_upload_files\./ nocase ascii wide
                        $string27_AlanFramework_offensive_tool_keyword = /agent_dll\.dll/ nocase ascii wide
                        $string28_AlanFramework_offensive_tool_keyword = /AlanFramework\.git/ nocase ascii wide
                        $string29_AlanFramework_offensive_tool_keyword = /c\:\\agent\.exe/ nocase ascii wide
                        $string30_AlanFramework_offensive_tool_keyword = /dotnet\s\.\/Server\.dll/
                        $string31_AlanFramework_offensive_tool_keyword = /DownloadString.{0,100}https\:\/\/checkip\.amazonaws\.com/ nocase ascii wide
                        $string32_AlanFramework_offensive_tool_keyword = /dump_lsass\.js/ nocase ascii wide
                        $string33_AlanFramework_offensive_tool_keyword = /dump_process\(.{0,100}lsass\.exe.{0,100}\)/ nocase ascii wide
                        $string34_AlanFramework_offensive_tool_keyword = "enkomio/AlanFramework" nocase ascii wide
                        $string35_AlanFramework_offensive_tool_keyword = /ES\.Alan\.Core\// nocase ascii wide
                        $string36_AlanFramework_offensive_tool_keyword = /http.{0,100}\:\/\/127\.0\.0\.1\:4433/ nocase ascii wide
                        $string37_AlanFramework_offensive_tool_keyword = /http.{0,100}\:\/\/127\.0\.0\.1\:5556/ nocase ascii wide
                        $string38_AlanFramework_offensive_tool_keyword = /http.{0,100}\:\/\/localhost\:4433/ nocase ascii wide
                        $string39_AlanFramework_offensive_tool_keyword = /http.{0,100}\:\/\/localhost\:5556/ nocase ascii wide
                        $string40_AlanFramework_offensive_tool_keyword = /pe_packer\/dll_main\.c/ nocase ascii wide
                        $string41_AlanFramework_offensive_tool_keyword = /pe_packer\/exe_main\.c/ nocase ascii wide
                        $string42_AlanFramework_offensive_tool_keyword = /pe_packer\/main\.c/ nocase ascii wide
                        $string43_AlanFramework_offensive_tool_keyword = /pe_packer\\dll_main\.c/ nocase ascii wide
                        $string44_AlanFramework_offensive_tool_keyword = /pe_packer\\exe_main\.c/ nocase ascii wide
                        $string45_AlanFramework_offensive_tool_keyword = /pe_packer\\main\.c/ nocase ascii wide
                        $string46_AlanFramework_offensive_tool_keyword = /pe_packer_exe\.exe/ nocase ascii wide
                        $string47_AlanFramework_offensive_tool_keyword = /powershell_command_x64\.ps1/ nocase ascii wide
                        $string48_AlanFramework_offensive_tool_keyword = /powershell_command_x86\.ps1/ nocase ascii wide
                        $string49_AlanFramework_offensive_tool_keyword = /socks5_exe\.exe/ nocase ascii wide
                        $string50_AlanFramework_offensive_tool_keyword = /stagerx64\.bin/ nocase ascii wide
                        $string51_AlanFramework_offensive_tool_keyword = "test_nanodump_exe" nocase ascii wide
                        $string52_AlanFramework_offensive_tool_keyword = "windows_agent/asm/x64/alter_pe_sections" nocase ascii wide
                        $string53_AlanFramework_offensive_tool_keyword = "windows_agent/asm/x86/alter_pe_sections" nocase ascii wide
                        $string54_AlanFramework_offensive_tool_keyword = /windows_agent\/dll_main\./ nocase ascii wide
                        $string55_AlanFramework_offensive_tool_keyword = /windows_agent\/exe_main\./ nocase ascii wide
                        $string56_AlanFramework_offensive_tool_keyword = /windows_agent\/win_.{0,100}\.c/ nocase ascii wide
                        $string57_AlanFramework_offensive_tool_keyword = /windows_agent\/win_named_pipe\./ nocase ascii wide
                        $string58_AlanFramework_offensive_tool_keyword = /windows_agent\/win_shell\./ nocase ascii wide
                        $string59_AlanFramework_offensive_tool_keyword = /windows_console_interceptor.{0,100}dll_main\.c/ nocase ascii wide
                        $string60_AlanFramework_offensive_tool_keyword = /windows_console_interceptor.{0,100}exe_main\.c/ nocase ascii wide
                        $string61_AlanFramework_offensive_tool_keyword = /windows_console_interceptor.{0,100}interceptor\./ nocase ascii wide
                        $string62_AlanFramework_offensive_tool_keyword = /x64PELoader\/.{0,100}\.exe/ nocase ascii wide
                        $string63_AlanFramework_offensive_tool_keyword = /x86PELoader\/.{0,100}\.exe/ nocase ascii wide
                        $string64_AlanFramework_offensive_tool_keyword = "x86PELoader/test_agent_dll" nocase ascii wide
                        $string65_AlanFramework_offensive_tool_keyword = "x86PELoader/test_agent_exe" nocase ascii wide
                        $string66_AlanFramework_offensive_tool_keyword = "x86PELoader/test_proxy_dll" nocase ascii wide
                        $string67_AlanFramework_offensive_tool_keyword = "x86PELoader/test_proxy_exe" nocase ascii wide
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