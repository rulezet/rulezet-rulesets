rule metasploit_payloads
{
    meta:
        description = "Detection patterns for the tool 'metasploit-payloads' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metasploit-payloads"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/credentials/enum_cred_store"
                        $string2 = "/credentials/enum_laps"
                        $string3 = "/gather/phish_windows_credentials"
                        $string4 = "/local_exploit_suggester"
                        $string5 = "capture/lockout_keylogger" nocase ascii wide
                        $string6 = "enum_ad_service_principal_names " nocase ascii wide
                        $string7 = "escalate/golden_ticket" nocase ascii wide
                        $string8 = "escalate/unmarshal_cmd_exec" nocase ascii wide
                        $string9 = "gather/credentials/rdc_manager_creds" nocase ascii wide
                        $string10 = "gather/credentials/teamviewer_passwords" nocase ascii wide
                        $string11 = "gather/credentials/windows_autologin" nocase ascii wide
                        $string12 = "gather/enum_ad_bitlocker" nocase ascii wide
                        $string13 = "gather/enum_ad_computers" nocase ascii wide
                        $string14 = "gather/enum_ad_groups" nocase ascii wide
                        $string15 = "gather/enum_ad_managedby_groups" nocase ascii wide
                        $string16 = "gather/enum_ad_to_wordlist" nocase ascii wide
                        $string17 = "gather/enum_ad_user_comments" nocase ascii wide
                        $string18 = "gather/enum_logged_on_users" nocase ascii wide
                        $string19 = "gather/enum_logged_on_users" nocase ascii wide
                        $string20 = "gather/enum_putty_saved_sessions" nocase ascii wide
                        $string21 = "manage/reflective_dll_inject" nocase ascii wide
                        $string22 = "metterpreter" nocase ascii wide
                        $string23 = /sniffer_dump\s.{0,1000}\/tmp\/.{0,1000}\.pcap/ nocase ascii wide
                        $string24 = "windows/gather/cachedump" nocase ascii wide
                        $string25 = "windows/gather/hashdump" nocase ascii wide

    condition:
        any of them
}