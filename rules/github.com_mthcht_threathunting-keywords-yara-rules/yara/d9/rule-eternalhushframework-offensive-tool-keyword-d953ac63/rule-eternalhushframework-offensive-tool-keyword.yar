rule rule_EternalHushFramework_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EternalHushFramework' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EternalHushFramework"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EternalHushFramework_offensive_tool_keyword = " EternalHushCore " nocase ascii wide
                        $string2_EternalHushFramework_offensive_tool_keyword = /\/EternalHushCore\.dll/ nocase ascii wide
                        $string3_EternalHushFramework_offensive_tool_keyword = /\/EternalHushFramework\.git/ nocase ascii wide
                        $string4_EternalHushFramework_offensive_tool_keyword = /\\EternalHushCore\.dll/ nocase ascii wide
                        $string5_EternalHushFramework_offensive_tool_keyword = /\\EternalHushCore\\/ nocase ascii wide
                        $string6_EternalHushFramework_offensive_tool_keyword = "APT64/EternalHushFramework" nocase ascii wide
                        $string7_EternalHushFramework_offensive_tool_keyword = /EternalHushFramework\-.{0,1000}\-SNAPSHOT\.jar/ nocase ascii wide
                        $string8_EternalHushFramework_offensive_tool_keyword = "EternalHushFramework-main" nocase ascii wide
                        $string9_EternalHushFramework_offensive_tool_keyword = /EternalHushMain\.java/ nocase ascii wide
                        $string10_EternalHushFramework_offensive_tool_keyword = /EternalHushWindow\.java/ nocase ascii wide
                        $string11_EternalHushFramework_offensive_tool_keyword = "import _eternalhush" nocase ascii wide
                        $string12_EternalHushFramework_offensive_tool_keyword = /import\seternalhush\./ nocase ascii wide
                        $string13_EternalHushFramework_offensive_tool_keyword = /SELECT\s.{0,1000}\sFROM\sEvilSignature/ nocase ascii wide
                        $string14_EternalHushFramework_offensive_tool_keyword = "W2F1dG9ydW5dDQpzaGVsbGV4ZWN1dGU9eTMyNHNlZHguZXhlDQppY29uPSVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxTSEVMTDMyLmRsbCw0DQphY3Rpb249T3BlbiBmb2xkZXIgdG8gdmlldyBmaWxlcw0Kc2hlbGxcZGVmYXVsdD1PcGVuDQpzaGVsbFxkZWZhdWx0XGNvbW1hbmQ9eTMyNHNlZHguZXhlDQpzaGVsbD1kZWZhdWx0" nocase ascii wide
                        $string15_EternalHushFramework_offensive_tool_keyword = /X32_ClSp_Tcp_Exe\.exe/ nocase ascii wide
                        $string16_EternalHushFramework_offensive_tool_keyword = /X64_ClSp_Tcp_Exe\.exe/ nocase ascii wide

    condition:
        any of them
}