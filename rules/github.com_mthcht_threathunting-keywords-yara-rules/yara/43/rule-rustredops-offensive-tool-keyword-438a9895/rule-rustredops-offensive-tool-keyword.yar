rule rule_RustRedOps_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RustRedOps' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustRedOps"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RustRedOps_offensive_tool_keyword = /\santi_analysis\.exe/ nocase ascii wide
                        $string2_RustRedOps_offensive_tool_keyword = /\santi_debug\.exe/ nocase ascii wide
                        $string3_RustRedOps_offensive_tool_keyword = /\sapc_injection\.exe/ nocase ascii wide
                        $string4_RustRedOps_offensive_tool_keyword = /\sapi_hooking\.exe/ nocase ascii wide
                        $string5_RustRedOps_offensive_tool_keyword = /\sargs_spoofing\-rs\.exe/ nocase ascii wide
                        $string6_RustRedOps_offensive_tool_keyword = /\sblock_dll_policy\.exe/ nocase ascii wide
                        $string7_RustRedOps_offensive_tool_keyword = /\scommand_exec\.exe/ nocase ascii wide
                        $string8_RustRedOps_offensive_tool_keyword = /\sdllinjection_rs\.exe/ nocase ascii wide
                        $string9_RustRedOps_offensive_tool_keyword = /\sebapc_injection\.exe/ nocase ascii wide
                        $string10_RustRedOps_offensive_tool_keyword = /\senable_all_tokens\.exe/ nocase ascii wide
                        $string11_RustRedOps_offensive_tool_keyword = /\sencryption_aes\.exe/ nocase ascii wide
                        $string12_RustRedOps_offensive_tool_keyword = /\sencryption_rc4\.exe/ nocase ascii wide
                        $string13_RustRedOps_offensive_tool_keyword = /\senumeration_process\.exe/ nocase ascii wide
                        $string14_RustRedOps_offensive_tool_keyword = /\sexecute_shellcode\.exe/ nocase ascii wide
                        $string15_RustRedOps_offensive_tool_keyword = /\sextract_wifi\.exe/ nocase ascii wide
                        $string16_RustRedOps_offensive_tool_keyword = /\siat_obfuscation\.exe/ nocase ascii wide
                        $string17_RustRedOps_offensive_tool_keyword = /\slfs_injection\.exe/ nocase ascii wide
                        $string18_RustRedOps_offensive_tool_keyword = /\slocal_execution_linux\.exe/
                        $string19_RustRedOps_offensive_tool_keyword = /\slocal_map\.exe/ nocase ascii wide
                        $string20_RustRedOps_offensive_tool_keyword = /\slocal_thread_hijacking\.exe/ nocase ascii wide
                        $string21_RustRedOps_offensive_tool_keyword = /\sminidump\-rs\.exe/ nocase ascii wide
                        $string22_RustRedOps_offensive_tool_keyword = /\sntdll_unhooking\.exe/ nocase ascii wide
                        $string23_RustRedOps_offensive_tool_keyword = /\sntdll_unhooking\.exe/ nocase ascii wide
                        $string24_RustRedOps_offensive_tool_keyword = /\sobfuscation\.exe\s\-\-help/ nocase ascii wide
                        $string25_RustRedOps_offensive_tool_keyword = /\s\-p\swindows\/x64\/exec\sCMD\=.{0,100}\.exe\s\-f\srust/ nocase ascii wide
                        $string26_RustRedOps_offensive_tool_keyword = /\spatch_amsi\.exe/ nocase ascii wide
                        $string27_RustRedOps_offensive_tool_keyword = /\spatch_etw\.exe/ nocase ascii wide
                        $string28_RustRedOps_offensive_tool_keyword = /\spayload_placement\.exe/ nocase ascii wide
                        $string29_RustRedOps_offensive_tool_keyword = /\sppid_spoofing\.exe/ nocase ascii wide
                        $string30_RustRedOps_offensive_tool_keyword = /\sprocessinjection\.exe/ nocase ascii wide
                        $string31_RustRedOps_offensive_tool_keyword = /\sreg_recover\-rs\.exe/ nocase ascii wide
                        $string32_RustRedOps_offensive_tool_keyword = /\srequest_shellcode\.exe/ nocase ascii wide
                        $string33_RustRedOps_offensive_tool_keyword = /\srfs_injection\.exe/ nocase ascii wide
                        $string34_RustRedOps_offensive_tool_keyword = /\srm_injection\.exe/ nocase ascii wide
                        $string35_RustRedOps_offensive_tool_keyword = /\srt_hijacking\.exe/ nocase ascii wide
                        $string36_RustRedOps_offensive_tool_keyword = /\sself_deletion\.exe/ nocase ascii wide
                        $string37_RustRedOps_offensive_tool_keyword = /\sshellcode_callback\.exe/ nocase ascii wide
                        $string38_RustRedOps_offensive_tool_keyword = /\swmi_exec\.exe/ nocase ascii wide
                        $string39_RustRedOps_offensive_tool_keyword = /\/anti_analysis\.exe/ nocase ascii wide
                        $string40_RustRedOps_offensive_tool_keyword = /\/anti_debug\.exe/ nocase ascii wide
                        $string41_RustRedOps_offensive_tool_keyword = /\/apc_injection\.exe/ nocase ascii wide
                        $string42_RustRedOps_offensive_tool_keyword = /\/api_hooking\.exe/ nocase ascii wide
                        $string43_RustRedOps_offensive_tool_keyword = /\/args_spoofing\-rs\.exe/ nocase ascii wide
                        $string44_RustRedOps_offensive_tool_keyword = /\/block_dll_policy\.exe/ nocase ascii wide
                        $string45_RustRedOps_offensive_tool_keyword = /\/command_exec\.exe/ nocase ascii wide
                        $string46_RustRedOps_offensive_tool_keyword = /\/dllinjection_rs\.exe/ nocase ascii wide
                        $string47_RustRedOps_offensive_tool_keyword = /\/ebapc_injection\.exe/ nocase ascii wide
                        $string48_RustRedOps_offensive_tool_keyword = /\/enable_all_tokens\.exe/ nocase ascii wide
                        $string49_RustRedOps_offensive_tool_keyword = /\/encryption_aes\.exe/ nocase ascii wide
                        $string50_RustRedOps_offensive_tool_keyword = /\/encryption_rc4\.exe/ nocase ascii wide
                        $string51_RustRedOps_offensive_tool_keyword = /\/enumeration_process\.exe/ nocase ascii wide
                        $string52_RustRedOps_offensive_tool_keyword = /\/execute_shellcode\.exe/ nocase ascii wide
                        $string53_RustRedOps_offensive_tool_keyword = /\/extract_wifi\.exe/ nocase ascii wide
                        $string54_RustRedOps_offensive_tool_keyword = /\/iat_obfuscation\.exe/ nocase ascii wide
                        $string55_RustRedOps_offensive_tool_keyword = /\/lfs_injection\.exe/ nocase ascii wide
                        $string56_RustRedOps_offensive_tool_keyword = /\/local_execution_linux\.exe/ nocase ascii wide
                        $string57_RustRedOps_offensive_tool_keyword = /\/local_map\.exe/ nocase ascii wide
                        $string58_RustRedOps_offensive_tool_keyword = /\/local_thread_hijacking\.exe/ nocase ascii wide
                        $string59_RustRedOps_offensive_tool_keyword = /\/minidump\-rs\.exe/ nocase ascii wide
                        $string60_RustRedOps_offensive_tool_keyword = /\/ntdll_unhooking\.exe/ nocase ascii wide
                        $string61_RustRedOps_offensive_tool_keyword = /\/ntdll_unhooking\.exe/ nocase ascii wide
                        $string62_RustRedOps_offensive_tool_keyword = /\/obfuscation\.exe\s\-\-help/ nocase ascii wide
                        $string63_RustRedOps_offensive_tool_keyword = /\/patch_amsi\.exe/ nocase ascii wide
                        $string64_RustRedOps_offensive_tool_keyword = /\/patch_etw\.exe/ nocase ascii wide
                        $string65_RustRedOps_offensive_tool_keyword = /\/payload_placement\.exe/ nocase ascii wide
                        $string66_RustRedOps_offensive_tool_keyword = /\/ppid_spoofing\.exe/ nocase ascii wide
                        $string67_RustRedOps_offensive_tool_keyword = /\/processinjection\.exe/ nocase ascii wide
                        $string68_RustRedOps_offensive_tool_keyword = /\/reg_recover\-rs\.exe/ nocase ascii wide
                        $string69_RustRedOps_offensive_tool_keyword = /\/request_shellcode\.exe/ nocase ascii wide
                        $string70_RustRedOps_offensive_tool_keyword = /\/rfs_injection\.exe/ nocase ascii wide
                        $string71_RustRedOps_offensive_tool_keyword = /\/rm_injection\.exe/ nocase ascii wide
                        $string72_RustRedOps_offensive_tool_keyword = /\/rt_hijacking\.exe/ nocase ascii wide
                        $string73_RustRedOps_offensive_tool_keyword = /\/RustRedOps\.git/ nocase ascii wide
                        $string74_RustRedOps_offensive_tool_keyword = /\/self_deletion\.exe/ nocase ascii wide
                        $string75_RustRedOps_offensive_tool_keyword = /\/shellcode_callback\.exe/ nocase ascii wide
                        $string76_RustRedOps_offensive_tool_keyword = /\/wmi_exec\.exe/ nocase ascii wide
                        $string77_RustRedOps_offensive_tool_keyword = /\[\+\]\sCopying\sa\sShellcode\sTo\sTarget\sMemory/ nocase ascii wide
                        $string78_RustRedOps_offensive_tool_keyword = /\\\\\.\\\\pipe\\\\Teste/ nocase ascii wide
                        $string79_RustRedOps_offensive_tool_keyword = /\\anti_analysis\.exe/ nocase ascii wide
                        $string80_RustRedOps_offensive_tool_keyword = /\\anti_debug\.exe/ nocase ascii wide
                        $string81_RustRedOps_offensive_tool_keyword = /\\apc_injection\.exe/ nocase ascii wide
                        $string82_RustRedOps_offensive_tool_keyword = /\\api_hooking\.exe/ nocase ascii wide
                        $string83_RustRedOps_offensive_tool_keyword = /\\args_spoofing\-rs\.exe/ nocase ascii wide
                        $string84_RustRedOps_offensive_tool_keyword = /\\block_dll_policy\.exe/ nocase ascii wide
                        $string85_RustRedOps_offensive_tool_keyword = /\\command_exec\.exe/ nocase ascii wide
                        $string86_RustRedOps_offensive_tool_keyword = /\\dllinjection_rs\.exe/ nocase ascii wide
                        $string87_RustRedOps_offensive_tool_keyword = /\\ebapc_injection\.exe/ nocase ascii wide
                        $string88_RustRedOps_offensive_tool_keyword = /\\enable_all_tokens\.exe/ nocase ascii wide
                        $string89_RustRedOps_offensive_tool_keyword = /\\encryption_aes\.exe/ nocase ascii wide
                        $string90_RustRedOps_offensive_tool_keyword = /\\encryption_rc4\.exe/ nocase ascii wide
                        $string91_RustRedOps_offensive_tool_keyword = /\\enumeration_process\.exe/ nocase ascii wide
                        $string92_RustRedOps_offensive_tool_keyword = /\\execute_shellcode\.exe/ nocase ascii wide
                        $string93_RustRedOps_offensive_tool_keyword = /\\extract_wifi\.exe/ nocase ascii wide
                        $string94_RustRedOps_offensive_tool_keyword = /\\iat_obfuscation\.exe/ nocase ascii wide
                        $string95_RustRedOps_offensive_tool_keyword = /\\lfs_injection\.exe/ nocase ascii wide
                        $string96_RustRedOps_offensive_tool_keyword = /\\local_execution_linux\.exe/ nocase ascii wide
                        $string97_RustRedOps_offensive_tool_keyword = /\\local_map\.exe/ nocase ascii wide
                        $string98_RustRedOps_offensive_tool_keyword = /\\local_thread_hijacking\.exe/ nocase ascii wide
                        $string99_RustRedOps_offensive_tool_keyword = /\\minidump\-rs\.exe/ nocase ascii wide
                        $string100_RustRedOps_offensive_tool_keyword = /\\ntdll_unhooking\.exe/ nocase ascii wide
                        $string101_RustRedOps_offensive_tool_keyword = /\\ntdll_unhooking\.exe/ nocase ascii wide
                        $string102_RustRedOps_offensive_tool_keyword = /\\obfuscation\.exe\s\-\-help/ nocase ascii wide
                        $string103_RustRedOps_offensive_tool_keyword = /\\patch_amsi\.exe/ nocase ascii wide
                        $string104_RustRedOps_offensive_tool_keyword = /\\patch_etw\.exe/ nocase ascii wide
                        $string105_RustRedOps_offensive_tool_keyword = /\\payload_placement\.exe/ nocase ascii wide
                        $string106_RustRedOps_offensive_tool_keyword = /\\ppid_spoofing\.exe/ nocase ascii wide
                        $string107_RustRedOps_offensive_tool_keyword = /\\processinjection\.exe/ nocase ascii wide
                        $string108_RustRedOps_offensive_tool_keyword = /\\reg_recover\-rs\.exe/ nocase ascii wide
                        $string109_RustRedOps_offensive_tool_keyword = /\\request_shellcode\.exe/ nocase ascii wide
                        $string110_RustRedOps_offensive_tool_keyword = /\\rfs_injection\.exe/ nocase ascii wide
                        $string111_RustRedOps_offensive_tool_keyword = /\\rm_injection\.exe/ nocase ascii wide
                        $string112_RustRedOps_offensive_tool_keyword = /\\rt_hijacking\.exe/ nocase ascii wide
                        $string113_RustRedOps_offensive_tool_keyword = /\\RustRedOps\\/ nocase ascii wide
                        $string114_RustRedOps_offensive_tool_keyword = /\\RustRedOps\-main/ nocase ascii wide
                        $string115_RustRedOps_offensive_tool_keyword = /\\self_deletion\.exe/ nocase ascii wide
                        $string116_RustRedOps_offensive_tool_keyword = /\\shellcode_callback\.exe/ nocase ascii wide
                        $string117_RustRedOps_offensive_tool_keyword = /\\Tasks\\lsass\.dmp/ nocase ascii wide
                        $string118_RustRedOps_offensive_tool_keyword = /\\wmi_exec\.exe/ nocase ascii wide
                        $string119_RustRedOps_offensive_tool_keyword = "joaoviictorti/RustRedOps" nocase ascii wide
                        $string120_RustRedOps_offensive_tool_keyword = /obfuscation\.exe\s\-\-/ nocase ascii wide
                        $string121_RustRedOps_offensive_tool_keyword = /obfuscation\.exe\s\-f\s.{0,100}\s\-t\s/ nocase ascii wide
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