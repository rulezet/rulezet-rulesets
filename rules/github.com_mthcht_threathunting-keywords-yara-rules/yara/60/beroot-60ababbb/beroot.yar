rule BeRoot
{
    meta:
        description = "Detection patterns for the tool 'BeRoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BeRoot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbeRoot\.exe/
                        $string2 = /\sbeRoot\.py/
                        $string3 = "-------------- Get System Priv with WebClient --------------" nocase ascii wide
                        $string4 = /\/beRoot\.exe/
                        $string5 = /\/BeRoot\.git/
                        $string6 = /\/beRoot\.py/
                        $string7 = /\/beRoot\.zip/
                        $string8 = "/BeRoot/Linux/"
                        $string9 = /\/beroot\/modules\/.{0,1000}\.py/ nocase ascii wide
                        $string10 = /\/gtfobins\.py/
                        $string11 = /\\beRoot\.exe/
                        $string12 = /\\beRoot\.zip/ nocase ascii wide
                        $string13 = /\\beroot\\modules\\.{0,1000}\.py/ nocase ascii wide
                        $string14 = /\\DLL_Hijacking\./ nocase ascii wide
                        $string15 = "52B0FF57-7E0A-4CA9-84D4-58DFA2456BA5" nocase ascii wide
                        $string16 = "AlessandroZ/BeRoot" nocase ascii wide
                        $string17 = /beRoot\.exe\s\-/
                        $string18 = /beroot\.py\s\-/
                        $string19 = "BeRoot-master"
                        $string20 = /from\s\.modules\.exploit\simport\sExploit/ nocase ascii wide
                        $string21 = /from\s\.secretsdump\simport\sRemoteOperations/ nocase ascii wide
                        $string22 = /Getting\spermissions\sof\ssensitive\sfiles\./ nocase ascii wide
                        $string23 = "import check_currrent_user_privilege" nocase ascii wide
                        $string24 = "import check_sudoers_misconfigurations"
                        $string25 = "linux-exploit-suggester"
                        $string26 = /modules\.gtfobins\simport\sGTFOBins/ nocase ascii wide
                        $string27 = /modules\.interesting_files\simport\sInterestingFiles/ nocase ascii wide

    condition:
        any of them
}