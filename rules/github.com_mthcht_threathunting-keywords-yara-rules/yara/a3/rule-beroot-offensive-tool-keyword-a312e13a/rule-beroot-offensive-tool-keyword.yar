rule rule_BeRoot_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BeRoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BeRoot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BeRoot_offensive_tool_keyword = /\sbeRoot\.exe/
                        $string2_BeRoot_offensive_tool_keyword = /\sbeRoot\.py/
                        $string3_BeRoot_offensive_tool_keyword = "-------------- Get System Priv with WebClient --------------" nocase ascii wide
                        $string4_BeRoot_offensive_tool_keyword = /\/beRoot\.exe/
                        $string5_BeRoot_offensive_tool_keyword = /\/BeRoot\.git/
                        $string6_BeRoot_offensive_tool_keyword = /\/beRoot\.py/
                        $string7_BeRoot_offensive_tool_keyword = /\/beRoot\.zip/
                        $string8_BeRoot_offensive_tool_keyword = "/BeRoot/Linux/"
                        $string9_BeRoot_offensive_tool_keyword = /\/beroot\/modules\/.{0,1000}\.py/ nocase ascii wide
                        $string10_BeRoot_offensive_tool_keyword = /\/gtfobins\.py/
                        $string11_BeRoot_offensive_tool_keyword = /\\beRoot\.exe/
                        $string12_BeRoot_offensive_tool_keyword = /\\beRoot\.zip/ nocase ascii wide
                        $string13_BeRoot_offensive_tool_keyword = /\\beroot\\modules\\.{0,1000}\.py/ nocase ascii wide
                        $string14_BeRoot_offensive_tool_keyword = /\\DLL_Hijacking\./ nocase ascii wide
                        $string15_BeRoot_offensive_tool_keyword = "52B0FF57-7E0A-4CA9-84D4-58DFA2456BA5" nocase ascii wide
                        $string16_BeRoot_offensive_tool_keyword = "AlessandroZ/BeRoot" nocase ascii wide
                        $string17_BeRoot_offensive_tool_keyword = /beRoot\.exe\s\-/
                        $string18_BeRoot_offensive_tool_keyword = /beroot\.py\s\-/
                        $string19_BeRoot_offensive_tool_keyword = "BeRoot-master"
                        $string20_BeRoot_offensive_tool_keyword = /from\s\.modules\.exploit\simport\sExploit/ nocase ascii wide
                        $string21_BeRoot_offensive_tool_keyword = /from\s\.secretsdump\simport\sRemoteOperations/ nocase ascii wide
                        $string22_BeRoot_offensive_tool_keyword = /Getting\spermissions\sof\ssensitive\sfiles\./ nocase ascii wide
                        $string23_BeRoot_offensive_tool_keyword = "import check_currrent_user_privilege" nocase ascii wide
                        $string24_BeRoot_offensive_tool_keyword = "import check_sudoers_misconfigurations"
                        $string25_BeRoot_offensive_tool_keyword = "linux-exploit-suggester"
                        $string26_BeRoot_offensive_tool_keyword = /modules\.gtfobins\simport\sGTFOBins/ nocase ascii wide
                        $string27_BeRoot_offensive_tool_keyword = /modules\.interesting_files\simport\sInterestingFiles/ nocase ascii wide

    condition:
        any of them
}