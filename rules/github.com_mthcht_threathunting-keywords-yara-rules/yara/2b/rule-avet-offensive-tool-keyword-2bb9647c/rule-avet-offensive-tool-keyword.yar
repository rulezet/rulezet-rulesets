rule rule_avet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'avet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "avet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_avet_offensive_tool_keyword = /\/avet\.git/ nocase ascii wide
                        $string2_avet_offensive_tool_keyword = /\/avet_script_config\.sh/ nocase ascii wide
                        $string3_avet_offensive_tool_keyword = /\\avetdbg\.txt/ nocase ascii wide
                        $string4_avet_offensive_tool_keyword = "add_evasion check_fast_forwarding" nocase ascii wide
                        $string5_avet_offensive_tool_keyword = "add_evasion computation_fibonacci " nocase ascii wide
                        $string6_avet_offensive_tool_keyword = "add_evasion computation_timed_fibonacci" nocase ascii wide
                        $string7_avet_offensive_tool_keyword = "add_evasion evasion_by_sleep " nocase ascii wide
                        $string8_avet_offensive_tool_keyword = "add_evasion fopen_sandbox_evasion" nocase ascii wide
                        $string9_avet_offensive_tool_keyword = "add_evasion get_bios_info" nocase ascii wide
                        $string10_avet_offensive_tool_keyword = "add_evasion get_computer_domain " nocase ascii wide
                        $string11_avet_offensive_tool_keyword = "add_evasion get_cpu_cores " nocase ascii wide
                        $string12_avet_offensive_tool_keyword = "add_evasion get_install_date " nocase ascii wide
                        $string13_avet_offensive_tool_keyword = "add_evasion get_num_processes" nocase ascii wide
                        $string14_avet_offensive_tool_keyword = "add_evasion get_standard_browser " nocase ascii wide
                        $string15_avet_offensive_tool_keyword = "add_evasion get_tickcount" nocase ascii wide
                        $string16_avet_offensive_tool_keyword = "add_evasion gethostbyname_sandbox_evasion" nocase ascii wide
                        $string17_avet_offensive_tool_keyword = "add_evasion has_background_wp" nocase ascii wide
                        $string18_avet_offensive_tool_keyword = "add_evasion has_folder " nocase ascii wide
                        $string19_avet_offensive_tool_keyword = "add_evasion has_network_drive" nocase ascii wide
                        $string20_avet_offensive_tool_keyword = "add_evasion has_public_desktop" nocase ascii wide
                        $string21_avet_offensive_tool_keyword = "add_evasion has_recent_files" nocase ascii wide
                        $string22_avet_offensive_tool_keyword = "add_evasion has_recycle_bin" nocase ascii wide
                        $string23_avet_offensive_tool_keyword = "add_evasion has_username " nocase ascii wide
                        $string24_avet_offensive_tool_keyword = "add_evasion has_vm_mac" nocase ascii wide
                        $string25_avet_offensive_tool_keyword = "add_evasion has_vm_regkey" nocase ascii wide
                        $string26_avet_offensive_tool_keyword = "add_evasion hide_console" nocase ascii wide
                        $string27_avet_offensive_tool_keyword = "add_evasion interaction_getchar" nocase ascii wide
                        $string28_avet_offensive_tool_keyword = "add_evasion interaction_system_pause" nocase ascii wide
                        $string29_avet_offensive_tool_keyword = "add_evasion is_debugger_present" nocase ascii wide
                        $string30_avet_offensive_tool_keyword = "add_evasion sleep_by_ping " nocase ascii wide
                        $string31_avet_offensive_tool_keyword = /avet\-master\.zip/ nocase ascii wide
                        $string32_avet_offensive_tool_keyword = /build_40xshikata_revhttpsunstaged_win32\.sh/ nocase ascii wide
                        $string33_avet_offensive_tool_keyword = /build_50xshikata_quiet_revhttps_win32\.sh/ nocase ascii wide
                        $string34_avet_offensive_tool_keyword = /build_50xshikata_revhttps_win32\.sh/ nocase ascii wide
                        $string35_avet_offensive_tool_keyword = /build_asciimsf_fromcmd_revhttps_win32\.sh/ nocase ascii wide
                        $string36_avet_offensive_tool_keyword = /build_asciimsf_revhttps_win32\.sh/ nocase ascii wide
                        $string37_avet_offensive_tool_keyword = /build_avetenc_dynamicfromfile_revhttps_win32\.sh/ nocase ascii wide
                        $string38_avet_offensive_tool_keyword = /build_avetenc_fopen_revhttps_win32\.sh/ nocase ascii wide
                        $string39_avet_offensive_tool_keyword = /build_avetenc_mtrprtrxor_revhttps_win64\.sh/ nocase ascii wide
                        $string40_avet_offensive_tool_keyword = /build_calcfromcmd_50xshikata_revhttps_win32\.sh/ nocase ascii wide
                        $string41_avet_offensive_tool_keyword = /build_calcfrompowersh_50xshikata_revhttps_win32\.sh/ nocase ascii wide
                        $string42_avet_offensive_tool_keyword = /build_checkdomain_rc4_mimikatz\.sh/ nocase ascii wide
                        $string43_avet_offensive_tool_keyword = /build_disablewindefpsh_xorfromcmd_revhttps_win64\.sh/ nocase ascii wide
                        $string44_avet_offensive_tool_keyword = /build_dkmc_downloadexecshc_revhttps_win32\.sh/ nocase ascii wide
                        $string45_avet_offensive_tool_keyword = /build_downloadbitsadmin_mtrprtrxor_revhttps_win64\.sh/ nocase ascii wide
                        $string46_avet_offensive_tool_keyword = /build_downloadbitsadmin_revhttps_win32\.sh/ nocase ascii wide
                        $string47_avet_offensive_tool_keyword = /build_downloadcertutil_revhttps_win32\.sh/ nocase ascii wide
                        $string48_avet_offensive_tool_keyword = /build_downloadcurl_mtrprtrxor_revhttps_win64\.sh/ nocase ascii wide
                        $string49_avet_offensive_tool_keyword = /build_sleep_rc4_mimikatz\.sh/ nocase ascii wide
                        $string50_avet_offensive_tool_keyword = /build_svc_20xshikata_bindtcp_win32\.sh/ nocase ascii wide
                        $string51_avet_offensive_tool_keyword = /encode_payload\src4\s.{0,1000}\.txt/ nocase ascii wide
                        $string52_avet_offensive_tool_keyword = /evasion\/has_recycle_bin\./ nocase ascii wide
                        $string53_avet_offensive_tool_keyword = "govolution/avet" nocase ascii wide
                        $string54_avet_offensive_tool_keyword = /input\/shellcode_enc_raw\.txt/ nocase ascii wide
                        $string55_avet_offensive_tool_keyword = /input\/shellcode_raw\.txt/ nocase ascii wide
                        $string56_avet_offensive_tool_keyword = /pe2shc\.exe/ nocase ascii wide
                        $string57_avet_offensive_tool_keyword = /pe2shc_.{0,1000}\.zip/ nocase ascii wide
                        $string58_avet_offensive_tool_keyword = "set_command_exec exec_via_cmd" nocase ascii wide
                        $string59_avet_offensive_tool_keyword = "set_command_exec exec_via_powershell" nocase ascii wide
                        $string60_avet_offensive_tool_keyword = "set_command_exec no_command" nocase ascii wide
                        $string61_avet_offensive_tool_keyword = "set_command_source download_bitsadmin" nocase ascii wide
                        $string62_avet_offensive_tool_keyword = "set_decoder xor" nocase ascii wide
                        $string63_avet_offensive_tool_keyword = "set_payload_execution_method exec_shellcode64" nocase ascii wide
                        $string64_avet_offensive_tool_keyword = "set_payload_execution_method inject_dll" nocase ascii wide
                        $string65_avet_offensive_tool_keyword = "set_payload_info_source from_command_line_raw" nocase ascii wide
                        $string66_avet_offensive_tool_keyword = "set_payload_source download_powershell" nocase ascii wide
                        $string67_avet_offensive_tool_keyword = /source\/avetsvc\.c/ nocase ascii wide

    condition:
        any of them
}