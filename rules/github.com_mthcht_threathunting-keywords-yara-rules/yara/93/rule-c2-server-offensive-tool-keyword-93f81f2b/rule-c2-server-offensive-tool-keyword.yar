rule rule_C2_Server_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'C2_Server' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2_Server"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_C2_Server_offensive_tool_keyword = /\srev_shell\.py/ nocase ascii wide
                        $string2_C2_Server_offensive_tool_keyword = /\/C2_Server\.git/ nocase ascii wide
                        $string3_C2_Server_offensive_tool_keyword = /\/rev_shell\.py/ nocase ascii wide
                        $string4_C2_Server_offensive_tool_keyword = /\[\+\]\sBack\sto\sC\&C\sConsole/ nocase ascii wide
                        $string5_C2_Server_offensive_tool_keyword = /\[\+\]\sKeylogger\sstarted/ nocase ascii wide
                        $string6_C2_Server_offensive_tool_keyword = /\[\+\]\sKeylogger\sstopped/ nocase ascii wide
                        $string7_C2_Server_offensive_tool_keyword = /\\\srev_shell\.py/ nocase ascii wide
                        $string8_C2_Server_offensive_tool_keyword = /\\Chrome_pass\.db/ nocase ascii wide
                        $string9_C2_Server_offensive_tool_keyword = /192\.168\.0\.110\:1234/ nocase ascii wide
                        $string10_C2_Server_offensive_tool_keyword = "C&C => " nocase ascii wide
                        $string11_C2_Server_offensive_tool_keyword = "C2_Server-main" nocase ascii wide
                        $string12_C2_Server_offensive_tool_keyword = /chrome_creds\.txt/ nocase ascii wide
                        $string13_C2_Server_offensive_tool_keyword = /Invoke\-WebRequest\shttps\:\/\/tinyurl\.com\// nocase ascii wide
                        $string14_C2_Server_offensive_tool_keyword = "keylog_dump" nocase ascii wide
                        $string15_C2_Server_offensive_tool_keyword = "keylog_off" nocase ascii wide
                        $string16_C2_Server_offensive_tool_keyword = "keylog_on" nocase ascii wide
                        $string17_C2_Server_offensive_tool_keyword = /lnx_keylogger\.py/ nocase ascii wide
                        $string18_C2_Server_offensive_tool_keyword = "reveng007/C2_Server" nocase ascii wide
                        $string19_C2_Server_offensive_tool_keyword = "spoof_wani" nocase ascii wide
                        $string20_C2_Server_offensive_tool_keyword = "spoof_wlan_creds" nocase ascii wide
                        $string21_C2_Server_offensive_tool_keyword = /win_chrome_password_extractor\.py/ nocase ascii wide
                        $string22_C2_Server_offensive_tool_keyword = /win_keylogger\.py/ nocase ascii wide
                        $string23_C2_Server_offensive_tool_keyword = /win_wlan_passwd_and_wanip_extractor\.py/ nocase ascii wide

    condition:
        any of them
}