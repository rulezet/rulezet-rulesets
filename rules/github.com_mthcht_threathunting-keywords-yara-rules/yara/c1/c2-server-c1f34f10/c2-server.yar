rule C2_Server
{
    meta:
        description = "Detection patterns for the tool 'C2_Server' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2_Server"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\srev_shell\.py/ nocase ascii wide
                        $string2 = /\/C2_Server\.git/ nocase ascii wide
                        $string3 = /\/rev_shell\.py/ nocase ascii wide
                        $string4 = /\[\+\]\sBack\sto\sC\&C\sConsole/ nocase ascii wide
                        $string5 = /\[\+\]\sKeylogger\sstarted/ nocase ascii wide
                        $string6 = /\[\+\]\sKeylogger\sstopped/ nocase ascii wide
                        $string7 = /\\\srev_shell\.py/ nocase ascii wide
                        $string8 = /\\Chrome_pass\.db/ nocase ascii wide
                        $string9 = /192\.168\.0\.110\:1234/ nocase ascii wide
                        $string10 = "C&C => " nocase ascii wide
                        $string11 = "C2_Server-main" nocase ascii wide
                        $string12 = /chrome_creds\.txt/ nocase ascii wide
                        $string13 = /Invoke\-WebRequest\shttps\:\/\/tinyurl\.com\// nocase ascii wide
                        $string14 = "keylog_dump" nocase ascii wide
                        $string15 = "keylog_off" nocase ascii wide
                        $string16 = "keylog_on" nocase ascii wide
                        $string17 = /lnx_keylogger\.py/ nocase ascii wide
                        $string18 = "reveng007/C2_Server" nocase ascii wide
                        $string19 = "spoof_wani" nocase ascii wide
                        $string20 = "spoof_wlan_creds" nocase ascii wide
                        $string21 = /win_chrome_password_extractor\.py/ nocase ascii wide
                        $string22 = /win_keylogger\.py/ nocase ascii wide
                        $string23 = /win_wlan_passwd_and_wanip_extractor\.py/ nocase ascii wide

    condition:
        any of them
}