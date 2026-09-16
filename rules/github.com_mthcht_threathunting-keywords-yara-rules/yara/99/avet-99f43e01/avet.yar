rule avet
{
    meta:
        description = "Detection patterns for the tool 'avet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "avet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/avet\.git/ nocase ascii wide
                        $string2 = /\/avet_script_config\.sh/ nocase ascii wide
                        $string3 = /\\avetdbg\.txt/ nocase ascii wide
                        $string4 = "add_evasion check_fast_forwarding" nocase ascii wide
                        $string5 = "add_evasion computation_fibonacci " nocase ascii wide
                        $string6 = "add_evasion computation_timed_fibonacci" nocase ascii wide
                        $string7 = "add_evasion evasion_by_sleep " nocase ascii wide
                        $string8 = "add_evasion fopen_sandbox_evasion" nocase ascii wide
                        $string9 = "add_evasion get_bios_info" nocase ascii wide
                        $string10 = "add_evasion get_computer_domain " nocase ascii wide
                        $string11 = "add_evasion get_cpu_cores " nocase ascii wide
                        $string12 = "add_evasion get_install_date " nocase ascii wide
                        $string13 = "add_evasion get_num_processes" nocase ascii wide
                        $string14 = "add_evasion get_standard_browser " nocase ascii wide
                        $string15 = "add_evasion get_tickcount" nocase ascii wide
                        $string16 = "add_evasion gethostbyname_sandbox_evasion" nocase ascii wide
                        $string17 = "add_evasion has_background_wp" nocase ascii wide
                        $string18 = "add_evasion has_folder " nocase ascii wide
                        $string19 = "add_evasion has_network_drive" nocase ascii wide
                        $string20 = "add_evasion has_public_desktop" nocase ascii wide
                        $string21 = "add_evasion has_recent_files" nocase ascii wide
                        $string22 = "add_evasion has_recycle_bin" nocase ascii wide
                        $string23 = "add_evasion has_username " nocase ascii wide
                        $string24 = "add_evasion has_vm_mac" nocase ascii wide
                        $string25 = "add_evasion has_vm_regkey" nocase ascii wide
                        $string26 = "add_evasion hide_console" nocase ascii wide
                        $string27 = "add_evasion interaction_getchar" nocase ascii wide
                        $string28 = "add_evasion interaction_system_pause" nocase ascii wide
                        $string29 = "add_evasion is_debugger_present" nocase ascii wide
                        $string30 = "add_evasion sleep_by_ping " nocase ascii wide
                        $string31 = /avet\-master\.zip/ nocase ascii wide
                        $string32 = /build_40xshikata_revhttpsunstaged_win32\.sh/ nocase ascii wide
                        $string33 = /build_50xshikata_quiet_revhttps_win32\.sh/ nocase ascii wide
                        $string34 = /build_50xshikata_revhttps_win32\.sh/ nocase ascii wide
                        $string35 = /build_asciimsf_fromcmd_revhttps_win32\.sh/ nocase ascii wide
                        $string36 = /build_asciimsf_revhttps_win32\.sh/ nocase ascii wide
                        $string37 = /build_avetenc_dynamicfromfile_revhttps_win32\.sh/ nocase ascii wide
                        $string38 = /build_avetenc_fopen_revhttps_win32\.sh/ nocase ascii wide
                        $string39 = /build_avetenc_mtrprtrxor_revhttps_win64\.sh/ nocase ascii wide
                        $string40 = /build_calcfromcmd_50xshikata_revhttps_win32\.sh/ nocase ascii wide
                        $string41 = /build_calcfrompowersh_50xshikata_revhttps_win32\.sh/ nocase ascii wide
                        $string42 = /build_checkdomain_rc4_mimikatz\.sh/ nocase ascii wide
                        $string43 = /build_disablewindefpsh_xorfromcmd_revhttps_win64\.sh/ nocase ascii wide
                        $string44 = /build_dkmc_downloadexecshc_revhttps_win32\.sh/ nocase ascii wide
                        $string45 = /build_downloadbitsadmin_mtrprtrxor_revhttps_win64\.sh/ nocase ascii wide
                        $string46 = /build_downloadbitsadmin_revhttps_win32\.sh/ nocase ascii wide
                        $string47 = /build_downloadcertutil_revhttps_win32\.sh/ nocase ascii wide
                        $string48 = /build_downloadcurl_mtrprtrxor_revhttps_win64\.sh/ nocase ascii wide
                        $string49 = /build_sleep_rc4_mimikatz\.sh/ nocase ascii wide
                        $string50 = /build_svc_20xshikata_bindtcp_win32\.sh/ nocase ascii wide
                        $string51 = /encode_payload\src4\s.{0,1000}\.txt/ nocase ascii wide
                        $string52 = /evasion\/has_recycle_bin\./ nocase ascii wide
                        $string53 = "govolution/avet" nocase ascii wide
                        $string54 = /input\/shellcode_enc_raw\.txt/ nocase ascii wide
                        $string55 = /input\/shellcode_raw\.txt/ nocase ascii wide
                        $string56 = /pe2shc\.exe/ nocase ascii wide
                        $string57 = /pe2shc_.{0,1000}\.zip/ nocase ascii wide
                        $string58 = "set_command_exec exec_via_cmd" nocase ascii wide
                        $string59 = "set_command_exec exec_via_powershell" nocase ascii wide
                        $string60 = "set_command_exec no_command" nocase ascii wide
                        $string61 = "set_command_source download_bitsadmin" nocase ascii wide
                        $string62 = "set_decoder xor" nocase ascii wide
                        $string63 = "set_payload_execution_method exec_shellcode64" nocase ascii wide
                        $string64 = "set_payload_execution_method inject_dll" nocase ascii wide
                        $string65 = "set_payload_info_source from_command_line_raw" nocase ascii wide
                        $string66 = "set_payload_source download_powershell" nocase ascii wide
                        $string67 = /source\/avetsvc\.c/ nocase ascii wide

    condition:
        any of them
}