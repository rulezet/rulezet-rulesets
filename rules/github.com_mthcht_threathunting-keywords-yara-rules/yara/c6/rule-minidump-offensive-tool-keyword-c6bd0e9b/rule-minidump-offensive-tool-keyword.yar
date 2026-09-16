rule rule_MiniDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MiniDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MiniDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MiniDump_offensive_tool_keyword = /\(Program\.MiniDump\sminidump/ nocase ascii wide
                        $string2_MiniDump_offensive_tool_keyword = /\/MiniDump\.git/ nocase ascii wide
                        $string3_MiniDump_offensive_tool_keyword = /\/MiniDump\-main\.zip/ nocase ascii wide
                        $string4_MiniDump_offensive_tool_keyword = /\\\\MiniDump\\\\Decryptor\\\\Credman/ nocase ascii wide
                        $string5_MiniDump_offensive_tool_keyword = /\\\\MiniDump\\\\Decryptor\\\\KerberosSessions/ nocase ascii wide
                        $string6_MiniDump_offensive_tool_keyword = /\\\\MiniDump\\\\Decryptor\\\\LogonSessions/ nocase ascii wide
                        $string7_MiniDump_offensive_tool_keyword = /\\\\windows\\\\temp\\\\lsass\.dmp/ nocase ascii wide
                        $string8_MiniDump_offensive_tool_keyword = /\\Minidump\.exe\sc\:\\/ nocase ascii wide
                        $string9_MiniDump_offensive_tool_keyword = /\\Minidump\.exe\\"\sc\:\\/ nocase ascii wide
                        $string10_MiniDump_offensive_tool_keyword = /\\MiniDump\-main/ nocase ascii wide
                        $string11_MiniDump_offensive_tool_keyword = "b2383e05411ba4a0e24dbfc67e5e4e1ddeae37acdf1137bccbf8d190d13c78a5" nocase ascii wide
                        $string12_MiniDump_offensive_tool_keyword = "BA1F3992-9654-4424-A0CC-26158FDFBF74" nocase ascii wide
                        $string13_MiniDump_offensive_tool_keyword = "cube0x0/MiniDump" nocase ascii wide
                        $string14_MiniDump_offensive_tool_keyword = "f038fdbc3ed50ebbf1ebc1c814836bcf93b4c149e5856ccf9b5400da8a974117" nocase ascii wide
                        $string15_MiniDump_offensive_tool_keyword = "lsadecryptor_lsa_decryptor" nocase ascii wide
                        $string16_MiniDump_offensive_tool_keyword = /minidump\.lsakeys/ nocase ascii wide
                        $string17_MiniDump_offensive_tool_keyword = /procdump64\.exe\s\-ma\slsass\.exe/ nocase ascii wide

    condition:
        any of them
}