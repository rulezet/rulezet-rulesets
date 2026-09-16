rule OffensiveCpp
{
    meta:
        description = "Detection patterns for the tool 'OffensiveCpp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveCpp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sadmin_persistence_winlogon\.c/ nocase ascii wide
                        $string2 = /\sSMB_Staging\.c/ nocase ascii wide
                        $string3 = /\suser_persistence_run\.c/ nocase ascii wide
                        $string4 = /\/admin_persistence_winlogon\.c/ nocase ascii wide
                        $string5 = /\/OffensiveCpp\.git/ nocase ascii wide
                        $string6 = /\/thread\-injector\.exe/ nocase ascii wide
                        $string7 = /\/user_persistence_run\.c/ nocase ascii wide
                        $string8 = /\\\\\\\\.{0,1000}\\\\share\\\\test\.bin/ nocase ascii wide
                        $string9 = /\\admin_persistence_winlogon/ nocase ascii wide
                        $string10 = /\\Evasion\\Sandbox\sEvasion\\.{0,1000}\.c/ nocase ascii wide
                        $string11 = /\\Evasion\\Sandbox\sEvasion\\.{0,1000}\.exe/ nocase ascii wide
                        $string12 = /\\OffensiveCpp\\/ nocase ascii wide
                        $string13 = /\\OffensiveCpp\-main/ nocase ascii wide
                        $string14 = /\\Shellcode\sExecution\\CertEnumSystemStore\\/ nocase ascii wide
                        $string15 = /\\Shellcode\sExecution\\Enum/ nocase ascii wide
                        $string16 = /\\SMB_Staging\.c/ nocase ascii wide
                        $string17 = /\\thread\-injector\.exe/ nocase ascii wide
                        $string18 = /\\user_persistence_run\.c/ nocase ascii wide
                        $string19 = /\]\sInjecting\sinto\sremote\sprocess\susing\sdirect\ssyscalls/ nocase ascii wide
                        $string20 = /\]\sInjecting\sinto\sremote\sprocess\susing\sdirect\ssyscalls/ nocase ascii wide
                        $string21 = "a8944d1ff8c72e68ca1bb55dad84aae6cb7d4cbcc92d442dc8497c8949a96adc" nocase ascii wide
                        $string22 = "d3366dc09c1ec4e93c9a40f4de0f96088786b6fb44b3fafb3d648a4b6342b596" nocase ascii wide
                        $string23 = "fbb4a1a49a0683247e83da8d2ccd4bdab51516a0a5cacbf6ff759213792e58e2" nocase ascii wide
                        $string24 = /If\sno\sprocess\sprovided\,\sit\swill\sattempt\sto\sinject\sinto\sexplorer\.exe/ nocase ascii wide
                        $string25 = "JohnWoodman/stealthInjector" nocase ascii wide
                        $string26 = "lsecqt/OffensiveCpp" nocase ascii wide
                        $string27 = "No sandbox-indicative DLLs were discovered loaded in any accessible running process" nocase ascii wide
                        $string28 = /thread\-injector\.exe\s/ nocase ascii wide

    condition:
        any of them
}