rule EDRaser
{
    meta:
        description = "Detection patterns for the tool 'EDRaser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRaser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-attack\sremote_db\s\-db_type\s.{0,1000}\s\-db_username\s.{0,1000}\s\-db_password\s/ nocase ascii wide
                        $string2 = " -attack windows_application_event_log_local" nocase ascii wide
                        $string3 = " -attack windows_event_log" nocase ascii wide
                        $string4 = " -attack windows_security_event_log_remote" nocase ascii wide
                        $string5 = " -attak syslog" nocase ascii wide
                        $string6 = /\sedraser\.py/ nocase ascii wide
                        $string7 = /\/EDRaser\.git/ nocase ascii wide
                        $string8 = /\/edraser\.py/ nocase ascii wide
                        $string9 = /\/evilSignatures\.db/ nocase ascii wide
                        $string10 = /\\edraser\.py/ nocase ascii wide
                        $string11 = /\\evilSignatures\.db/ nocase ascii wide
                        $string12 = /edraser\.py\s\-/ nocase ascii wide
                        $string13 = "EDRaser-main" nocase ascii wide
                        $string14 = "SafeBreach-Labs/EDRaser" nocase ascii wide
                        $string15 = /SELECT\s.{0,1000}\sFROM\sEvilSignature/ nocase ascii wide
                        $string16 = "W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0" nocase ascii wide

    condition:
        any of them
}