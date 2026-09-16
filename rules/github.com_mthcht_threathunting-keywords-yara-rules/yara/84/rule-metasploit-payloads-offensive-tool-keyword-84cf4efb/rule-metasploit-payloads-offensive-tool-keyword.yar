rule rule_metasploit_payloads_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'metasploit-payloads' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metasploit-payloads"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_metasploit_payloads_offensive_tool_keyword = "/credentials/enum_cred_store"
                        $string2_metasploit_payloads_offensive_tool_keyword = "/credentials/enum_laps"
                        $string3_metasploit_payloads_offensive_tool_keyword = "/gather/phish_windows_credentials"
                        $string4_metasploit_payloads_offensive_tool_keyword = "/local_exploit_suggester"
                        $string5_metasploit_payloads_offensive_tool_keyword = "capture/lockout_keylogger" nocase ascii wide
                        $string6_metasploit_payloads_offensive_tool_keyword = "enum_ad_service_principal_names " nocase ascii wide
                        $string7_metasploit_payloads_offensive_tool_keyword = "escalate/golden_ticket" nocase ascii wide
                        $string8_metasploit_payloads_offensive_tool_keyword = "escalate/unmarshal_cmd_exec" nocase ascii wide
                        $string9_metasploit_payloads_offensive_tool_keyword = "gather/credentials/rdc_manager_creds" nocase ascii wide
                        $string10_metasploit_payloads_offensive_tool_keyword = "gather/credentials/teamviewer_passwords" nocase ascii wide
                        $string11_metasploit_payloads_offensive_tool_keyword = "gather/credentials/windows_autologin" nocase ascii wide
                        $string12_metasploit_payloads_offensive_tool_keyword = "gather/enum_ad_bitlocker" nocase ascii wide
                        $string13_metasploit_payloads_offensive_tool_keyword = "gather/enum_ad_computers" nocase ascii wide
                        $string14_metasploit_payloads_offensive_tool_keyword = "gather/enum_ad_groups" nocase ascii wide
                        $string15_metasploit_payloads_offensive_tool_keyword = "gather/enum_ad_managedby_groups" nocase ascii wide
                        $string16_metasploit_payloads_offensive_tool_keyword = "gather/enum_ad_to_wordlist" nocase ascii wide
                        $string17_metasploit_payloads_offensive_tool_keyword = "gather/enum_ad_user_comments" nocase ascii wide
                        $string18_metasploit_payloads_offensive_tool_keyword = "gather/enum_logged_on_users" nocase ascii wide
                        $string19_metasploit_payloads_offensive_tool_keyword = "gather/enum_logged_on_users" nocase ascii wide
                        $string20_metasploit_payloads_offensive_tool_keyword = "gather/enum_putty_saved_sessions" nocase ascii wide
                        $string21_metasploit_payloads_offensive_tool_keyword = "manage/reflective_dll_inject" nocase ascii wide
                        $string22_metasploit_payloads_offensive_tool_keyword = "metterpreter" nocase ascii wide
                        $string23_metasploit_payloads_offensive_tool_keyword = /sniffer_dump\s.{0,1000}\/tmp\/.{0,1000}\.pcap/ nocase ascii wide
                        $string24_metasploit_payloads_offensive_tool_keyword = "windows/gather/cachedump" nocase ascii wide
                        $string25_metasploit_payloads_offensive_tool_keyword = "windows/gather/hashdump" nocase ascii wide

    condition:
        any of them
}