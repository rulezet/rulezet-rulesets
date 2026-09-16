rule EDRaser
{
    meta:
        description = "Detection patterns for the tool 'EDRaser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRaser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-attack\sremote_db\s\-db_type\s.{0,100}\s\-db_username\s.{0,100}\s\-db_password\s/ nocase ascii wide
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
                        $string15 = /SELECT\s.{0,100}\sFROM\sEvilSignature/ nocase ascii wide
                        $string16 = "W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}