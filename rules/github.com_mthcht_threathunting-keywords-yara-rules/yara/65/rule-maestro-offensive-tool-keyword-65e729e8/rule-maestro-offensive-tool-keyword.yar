rule rule_Maestro_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Maestro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Maestro"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Maestro_offensive_tool_keyword = /\\ROADtoken\\bin\\/ nocase ascii wide
                        $string2_Maestro_offensive_tool_keyword = "4EE2C7E8-095D-490A-9465-9B4BB9070669" nocase ascii wide
                        $string3_Maestro_offensive_tool_keyword = "8fff8971be038906411561230e11adae6f576dca6761375cbcf61d3e7b2e4cd4" nocase ascii wide
                        $string4_Maestro_offensive_tool_keyword = /await\sDeleteIntuneCommand\.Exe/ nocase ascii wide
                        $string5_Maestro_offensive_tool_keyword = /await\sDeleteIntuneScriptCommand\.Exe/ nocase ascii wide
                        $string6_Maestro_offensive_tool_keyword = /await\sExecIntuneAppCommand\.Exe/ nocase ascii wide
                        $string7_Maestro_offensive_tool_keyword = /await\sExecIntuneCommand\.Exe/ nocase ascii wide
                        $string8_Maestro_offensive_tool_keyword = /await\sExecIntuneDeviceQueryCommand\.Exe/ nocase ascii wide
                        $string9_Maestro_offensive_tool_keyword = /await\sExecIntuneScriptCommand\.Exe/ nocase ascii wide
                        $string10_Maestro_offensive_tool_keyword = /await\sExecIntuneSyncCommand\.Exe/ nocase ascii wide
                        $string11_Maestro_offensive_tool_keyword = /await\sGetAccessTokenCommand\.Exe/ nocase ascii wide
                        $string12_Maestro_offensive_tool_keyword = /await\sGetEntraCommand\.Exe/ nocase ascii wide
                        $string13_Maestro_offensive_tool_keyword = /await\sGetEntraGroupsCommand\.Exe/ nocase ascii wide
                        $string14_Maestro_offensive_tool_keyword = /await\sGetEntraUsersCommand\.Exe/ nocase ascii wide
                        $string15_Maestro_offensive_tool_keyword = /await\sGetIntuneAppsCommand\.Exe/ nocase ascii wide
                        $string16_Maestro_offensive_tool_keyword = /await\sGetIntuneCommand\.Exe/ nocase ascii wide
                        $string17_Maestro_offensive_tool_keyword = /await\sGetIntuneDevicesCommand\.Exe/ nocase ascii wide
                        $string18_Maestro_offensive_tool_keyword = /await\sGetIntuneScriptsCommand\.Exe/ nocase ascii wide
                        $string19_Maestro_offensive_tool_keyword = /await\sGetPrtCookieCommand\.Exe/ nocase ascii wide
                        $string20_Maestro_offensive_tool_keyword = "c0ec4fdda78c68d5b982664a121efb8939808171d11d7a1e9bc17db565d99ee1" nocase ascii wide
                        $string21_Maestro_offensive_tool_keyword = "C9AF8FE1-CDFC-4DDD-B314-B44AD5EAD552" nocase ascii wide
                        $string22_Maestro_offensive_tool_keyword = /dsregcmd\.exe\s\/status/ nocase ascii wide
                        $string23_Maestro_offensive_tool_keyword = /maestro\.exe\sexec/ nocase ascii wide
                        $string24_Maestro_offensive_tool_keyword = "Mayyhem/Maestro" nocase ascii wide
                        $string25_Maestro_offensive_tool_keyword = /RequestAADRefreshToken\.exe/ nocase ascii wide
                        $string26_Maestro_offensive_tool_keyword = /roadtoken\.exe/ nocase ascii wide
                        $string27_Maestro_offensive_tool_keyword = "RVLextu9ni633iqW54ktzkU4kTDgekRFY8ao9gSwM78=" nocase ascii wide

    condition:
        any of them
}