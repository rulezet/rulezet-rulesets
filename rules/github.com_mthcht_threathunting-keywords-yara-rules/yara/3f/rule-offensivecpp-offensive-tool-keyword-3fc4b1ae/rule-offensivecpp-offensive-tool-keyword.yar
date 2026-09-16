rule rule_OffensiveCpp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OffensiveCpp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveCpp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OffensiveCpp_offensive_tool_keyword = /\sadmin_persistence_winlogon\.c/ nocase ascii wide
                        $string2_OffensiveCpp_offensive_tool_keyword = /\sSMB_Staging\.c/ nocase ascii wide
                        $string3_OffensiveCpp_offensive_tool_keyword = /\suser_persistence_run\.c/ nocase ascii wide
                        $string4_OffensiveCpp_offensive_tool_keyword = /\/admin_persistence_winlogon\.c/ nocase ascii wide
                        $string5_OffensiveCpp_offensive_tool_keyword = /\/OffensiveCpp\.git/ nocase ascii wide
                        $string6_OffensiveCpp_offensive_tool_keyword = /\/thread\-injector\.exe/ nocase ascii wide
                        $string7_OffensiveCpp_offensive_tool_keyword = /\/user_persistence_run\.c/ nocase ascii wide
                        $string8_OffensiveCpp_offensive_tool_keyword = /\\\\\\\\.{0,1000}\\\\share\\\\test\.bin/ nocase ascii wide
                        $string9_OffensiveCpp_offensive_tool_keyword = /\\admin_persistence_winlogon/ nocase ascii wide
                        $string10_OffensiveCpp_offensive_tool_keyword = /\\Evasion\\Sandbox\sEvasion\\.{0,1000}\.c/ nocase ascii wide
                        $string11_OffensiveCpp_offensive_tool_keyword = /\\Evasion\\Sandbox\sEvasion\\.{0,1000}\.exe/ nocase ascii wide
                        $string12_OffensiveCpp_offensive_tool_keyword = /\\OffensiveCpp\\/ nocase ascii wide
                        $string13_OffensiveCpp_offensive_tool_keyword = /\\OffensiveCpp\-main/ nocase ascii wide
                        $string14_OffensiveCpp_offensive_tool_keyword = /\\Shellcode\sExecution\\CertEnumSystemStore\\/ nocase ascii wide
                        $string15_OffensiveCpp_offensive_tool_keyword = /\\Shellcode\sExecution\\Enum/ nocase ascii wide
                        $string16_OffensiveCpp_offensive_tool_keyword = /\\SMB_Staging\.c/ nocase ascii wide
                        $string17_OffensiveCpp_offensive_tool_keyword = /\\thread\-injector\.exe/ nocase ascii wide
                        $string18_OffensiveCpp_offensive_tool_keyword = /\\user_persistence_run\.c/ nocase ascii wide
                        $string19_OffensiveCpp_offensive_tool_keyword = /\]\sInjecting\sinto\sremote\sprocess\susing\sdirect\ssyscalls/ nocase ascii wide
                        $string20_OffensiveCpp_offensive_tool_keyword = /\]\sInjecting\sinto\sremote\sprocess\susing\sdirect\ssyscalls/ nocase ascii wide
                        $string21_OffensiveCpp_offensive_tool_keyword = "a8944d1ff8c72e68ca1bb55dad84aae6cb7d4cbcc92d442dc8497c8949a96adc" nocase ascii wide
                        $string22_OffensiveCpp_offensive_tool_keyword = "d3366dc09c1ec4e93c9a40f4de0f96088786b6fb44b3fafb3d648a4b6342b596" nocase ascii wide
                        $string23_OffensiveCpp_offensive_tool_keyword = "fbb4a1a49a0683247e83da8d2ccd4bdab51516a0a5cacbf6ff759213792e58e2" nocase ascii wide
                        $string24_OffensiveCpp_offensive_tool_keyword = /If\sno\sprocess\sprovided\,\sit\swill\sattempt\sto\sinject\sinto\sexplorer\.exe/ nocase ascii wide
                        $string25_OffensiveCpp_offensive_tool_keyword = "JohnWoodman/stealthInjector" nocase ascii wide
                        $string26_OffensiveCpp_offensive_tool_keyword = "lsecqt/OffensiveCpp" nocase ascii wide
                        $string27_OffensiveCpp_offensive_tool_keyword = "No sandbox-indicative DLLs were discovered loaded in any accessible running process" nocase ascii wide
                        $string28_OffensiveCpp_offensive_tool_keyword = /thread\-injector\.exe\s/ nocase ascii wide

    condition:
        any of them
}