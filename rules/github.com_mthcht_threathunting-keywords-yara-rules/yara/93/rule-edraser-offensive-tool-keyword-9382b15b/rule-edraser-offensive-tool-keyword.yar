rule rule_EDRaser_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EDRaser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRaser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EDRaser_offensive_tool_keyword = /\s\-attack\sremote_db\s\-db_type\s.{0,1000}\s\-db_username\s.{0,1000}\s\-db_password\s/ nocase ascii wide
                        $string2_EDRaser_offensive_tool_keyword = " -attack windows_application_event_log_local" nocase ascii wide
                        $string3_EDRaser_offensive_tool_keyword = " -attack windows_event_log" nocase ascii wide
                        $string4_EDRaser_offensive_tool_keyword = " -attack windows_security_event_log_remote" nocase ascii wide
                        $string5_EDRaser_offensive_tool_keyword = " -attak syslog" nocase ascii wide
                        $string6_EDRaser_offensive_tool_keyword = /\sedraser\.py/ nocase ascii wide
                        $string7_EDRaser_offensive_tool_keyword = /\/EDRaser\.git/ nocase ascii wide
                        $string8_EDRaser_offensive_tool_keyword = /\/edraser\.py/ nocase ascii wide
                        $string9_EDRaser_offensive_tool_keyword = /\/evilSignatures\.db/ nocase ascii wide
                        $string10_EDRaser_offensive_tool_keyword = /\\edraser\.py/ nocase ascii wide
                        $string11_EDRaser_offensive_tool_keyword = /\\evilSignatures\.db/ nocase ascii wide
                        $string12_EDRaser_offensive_tool_keyword = /edraser\.py\s\-/ nocase ascii wide
                        $string13_EDRaser_offensive_tool_keyword = "EDRaser-main" nocase ascii wide
                        $string14_EDRaser_offensive_tool_keyword = "SafeBreach-Labs/EDRaser" nocase ascii wide
                        $string15_EDRaser_offensive_tool_keyword = /SELECT\s.{0,1000}\sFROM\sEvilSignature/ nocase ascii wide
                        $string16_EDRaser_offensive_tool_keyword = "W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0" nocase ascii wide

    condition:
        any of them
}