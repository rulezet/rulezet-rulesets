rule RustRedOps
{
    meta:
        description = "Detection patterns for the tool 'RustRedOps' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustRedOps"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\santi_analysis\.exe/ nocase ascii wide
                        $string2 = /\santi_debug\.exe/ nocase ascii wide
                        $string3 = /\sapc_injection\.exe/ nocase ascii wide
                        $string4 = /\sapi_hooking\.exe/ nocase ascii wide
                        $string5 = /\sargs_spoofing\-rs\.exe/ nocase ascii wide
                        $string6 = /\sblock_dll_policy\.exe/ nocase ascii wide
                        $string7 = /\scommand_exec\.exe/ nocase ascii wide
                        $string8 = /\sdllinjection_rs\.exe/ nocase ascii wide
                        $string9 = /\sebapc_injection\.exe/ nocase ascii wide
                        $string10 = /\senable_all_tokens\.exe/ nocase ascii wide
                        $string11 = /\sencryption_aes\.exe/ nocase ascii wide
                        $string12 = /\sencryption_rc4\.exe/ nocase ascii wide
                        $string13 = /\senumeration_process\.exe/ nocase ascii wide
                        $string14 = /\sexecute_shellcode\.exe/ nocase ascii wide
                        $string15 = /\sextract_wifi\.exe/ nocase ascii wide
                        $string16 = /\siat_obfuscation\.exe/ nocase ascii wide
                        $string17 = /\slfs_injection\.exe/ nocase ascii wide
                        $string18 = /\slocal_execution_linux\.exe/
                        $string19 = /\slocal_map\.exe/ nocase ascii wide
                        $string20 = /\slocal_thread_hijacking\.exe/ nocase ascii wide
                        $string21 = /\sminidump\-rs\.exe/ nocase ascii wide
                        $string22 = /\sntdll_unhooking\.exe/ nocase ascii wide
                        $string23 = /\sntdll_unhooking\.exe/ nocase ascii wide
                        $string24 = /\sobfuscation\.exe\s\-\-help/ nocase ascii wide
                        $string25 = /\s\-p\swindows\/x64\/exec\sCMD\=.{0,100}\.exe\s\-f\srust/ nocase ascii wide
                        $string26 = /\spatch_amsi\.exe/ nocase ascii wide
                        $string27 = /\spatch_etw\.exe/ nocase ascii wide
                        $string28 = /\spayload_placement\.exe/ nocase ascii wide
                        $string29 = /\sppid_spoofing\.exe/ nocase ascii wide
                        $string30 = /\sprocessinjection\.exe/ nocase ascii wide
                        $string31 = /\sreg_recover\-rs\.exe/ nocase ascii wide
                        $string32 = /\srequest_shellcode\.exe/ nocase ascii wide
                        $string33 = /\srfs_injection\.exe/ nocase ascii wide
                        $string34 = /\srm_injection\.exe/ nocase ascii wide
                        $string35 = /\srt_hijacking\.exe/ nocase ascii wide
                        $string36 = /\sself_deletion\.exe/ nocase ascii wide
                        $string37 = /\sshellcode_callback\.exe/ nocase ascii wide
                        $string38 = /\swmi_exec\.exe/ nocase ascii wide
                        $string39 = /\/anti_analysis\.exe/ nocase ascii wide
                        $string40 = /\/anti_debug\.exe/ nocase ascii wide
                        $string41 = /\/apc_injection\.exe/ nocase ascii wide
                        $string42 = /\/api_hooking\.exe/ nocase ascii wide
                        $string43 = /\/args_spoofing\-rs\.exe/ nocase ascii wide
                        $string44 = /\/block_dll_policy\.exe/ nocase ascii wide
                        $string45 = /\/command_exec\.exe/ nocase ascii wide
                        $string46 = /\/dllinjection_rs\.exe/ nocase ascii wide
                        $string47 = /\/ebapc_injection\.exe/ nocase ascii wide
                        $string48 = /\/enable_all_tokens\.exe/ nocase ascii wide
                        $string49 = /\/encryption_aes\.exe/ nocase ascii wide
                        $string50 = /\/encryption_rc4\.exe/ nocase ascii wide
                        $string51 = /\/enumeration_process\.exe/ nocase ascii wide
                        $string52 = /\/execute_shellcode\.exe/ nocase ascii wide
                        $string53 = /\/extract_wifi\.exe/ nocase ascii wide
                        $string54 = /\/iat_obfuscation\.exe/ nocase ascii wide
                        $string55 = /\/lfs_injection\.exe/ nocase ascii wide
                        $string56 = /\/local_execution_linux\.exe/ nocase ascii wide
                        $string57 = /\/local_map\.exe/ nocase ascii wide
                        $string58 = /\/local_thread_hijacking\.exe/ nocase ascii wide
                        $string59 = /\/minidump\-rs\.exe/ nocase ascii wide
                        $string60 = /\/ntdll_unhooking\.exe/ nocase ascii wide
                        $string61 = /\/ntdll_unhooking\.exe/ nocase ascii wide
                        $string62 = /\/obfuscation\.exe\s\-\-help/ nocase ascii wide
                        $string63 = /\/patch_amsi\.exe/ nocase ascii wide
                        $string64 = /\/patch_etw\.exe/ nocase ascii wide
                        $string65 = /\/payload_placement\.exe/ nocase ascii wide
                        $string66 = /\/ppid_spoofing\.exe/ nocase ascii wide
                        $string67 = /\/processinjection\.exe/ nocase ascii wide
                        $string68 = /\/reg_recover\-rs\.exe/ nocase ascii wide
                        $string69 = /\/request_shellcode\.exe/ nocase ascii wide
                        $string70 = /\/rfs_injection\.exe/ nocase ascii wide
                        $string71 = /\/rm_injection\.exe/ nocase ascii wide
                        $string72 = /\/rt_hijacking\.exe/ nocase ascii wide
                        $string73 = /\/RustRedOps\.git/ nocase ascii wide
                        $string74 = /\/self_deletion\.exe/ nocase ascii wide
                        $string75 = /\/shellcode_callback\.exe/ nocase ascii wide
                        $string76 = /\/wmi_exec\.exe/ nocase ascii wide
                        $string77 = /\[\+\]\sCopying\sa\sShellcode\sTo\sTarget\sMemory/ nocase ascii wide
                        $string78 = /\\\\\.\\\\pipe\\\\Teste/ nocase ascii wide
                        $string79 = /\\anti_analysis\.exe/ nocase ascii wide
                        $string80 = /\\anti_debug\.exe/ nocase ascii wide
                        $string81 = /\\apc_injection\.exe/ nocase ascii wide
                        $string82 = /\\api_hooking\.exe/ nocase ascii wide
                        $string83 = /\\args_spoofing\-rs\.exe/ nocase ascii wide
                        $string84 = /\\block_dll_policy\.exe/ nocase ascii wide
                        $string85 = /\\command_exec\.exe/ nocase ascii wide
                        $string86 = /\\dllinjection_rs\.exe/ nocase ascii wide
                        $string87 = /\\ebapc_injection\.exe/ nocase ascii wide
                        $string88 = /\\enable_all_tokens\.exe/ nocase ascii wide
                        $string89 = /\\encryption_aes\.exe/ nocase ascii wide
                        $string90 = /\\encryption_rc4\.exe/ nocase ascii wide
                        $string91 = /\\enumeration_process\.exe/ nocase ascii wide
                        $string92 = /\\execute_shellcode\.exe/ nocase ascii wide
                        $string93 = /\\extract_wifi\.exe/ nocase ascii wide
                        $string94 = /\\iat_obfuscation\.exe/ nocase ascii wide
                        $string95 = /\\lfs_injection\.exe/ nocase ascii wide
                        $string96 = /\\local_execution_linux\.exe/ nocase ascii wide
                        $string97 = /\\local_map\.exe/ nocase ascii wide
                        $string98 = /\\local_thread_hijacking\.exe/ nocase ascii wide
                        $string99 = /\\minidump\-rs\.exe/ nocase ascii wide
                        $string100 = /\\ntdll_unhooking\.exe/ nocase ascii wide
                        $string101 = /\\ntdll_unhooking\.exe/ nocase ascii wide
                        $string102 = /\\obfuscation\.exe\s\-\-help/ nocase ascii wide
                        $string103 = /\\patch_amsi\.exe/ nocase ascii wide
                        $string104 = /\\patch_etw\.exe/ nocase ascii wide
                        $string105 = /\\payload_placement\.exe/ nocase ascii wide
                        $string106 = /\\ppid_spoofing\.exe/ nocase ascii wide
                        $string107 = /\\processinjection\.exe/ nocase ascii wide
                        $string108 = /\\reg_recover\-rs\.exe/ nocase ascii wide
                        $string109 = /\\request_shellcode\.exe/ nocase ascii wide
                        $string110 = /\\rfs_injection\.exe/ nocase ascii wide
                        $string111 = /\\rm_injection\.exe/ nocase ascii wide
                        $string112 = /\\rt_hijacking\.exe/ nocase ascii wide
                        $string113 = /\\RustRedOps\\/ nocase ascii wide
                        $string114 = /\\RustRedOps\-main/ nocase ascii wide
                        $string115 = /\\self_deletion\.exe/ nocase ascii wide
                        $string116 = /\\shellcode_callback\.exe/ nocase ascii wide
                        $string117 = /\\Tasks\\lsass\.dmp/ nocase ascii wide
                        $string118 = /\\wmi_exec\.exe/ nocase ascii wide
                        $string119 = "joaoviictorti/RustRedOps" nocase ascii wide
                        $string120 = /obfuscation\.exe\s\-\-/ nocase ascii wide
                        $string121 = /obfuscation\.exe\s\-f\s.{0,100}\s\-t\s/ nocase ascii wide
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