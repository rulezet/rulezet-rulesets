rule EternalHushFramework
{
    meta:
        description = "Detection patterns for the tool 'EternalHushFramework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EternalHushFramework"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " EternalHushCore " nocase ascii wide
                        $string2 = /\/EternalHushCore\.dll/ nocase ascii wide
                        $string3 = /\/EternalHushFramework\.git/ nocase ascii wide
                        $string4 = /\\EternalHushCore\.dll/ nocase ascii wide
                        $string5 = /\\EternalHushCore\\/ nocase ascii wide
                        $string6 = "APT64/EternalHushFramework" nocase ascii wide
                        $string7 = /EternalHushFramework\-.{0,1000}\-SNAPSHOT\.jar/ nocase ascii wide
                        $string8 = "EternalHushFramework-main" nocase ascii wide
                        $string9 = /EternalHushMain\.java/ nocase ascii wide
                        $string10 = /EternalHushWindow\.java/ nocase ascii wide
                        $string11 = "import _eternalhush" nocase ascii wide
                        $string12 = /import\seternalhush\./ nocase ascii wide
                        $string13 = /SELECT\s.{0,1000}\sFROM\sEvilSignature/ nocase ascii wide
                        $string14 = "W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0" nocase ascii wide
                        $string15 = /X32_ClSp_Tcp_Exe\.exe/ nocase ascii wide
                        $string16 = /X64_ClSp_Tcp_Exe\.exe/ nocase ascii wide

    condition:
        any of them
}