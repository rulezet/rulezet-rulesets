rule rule_Perfusion_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Perfusion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Perfusion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Perfusion_offensive_tool_keyword = /\/Perfusion\.exe/ nocase ascii wide
                        $string2_Perfusion_offensive_tool_keyword = /\/Perfusion\.git/ nocase ascii wide
                        $string3_Perfusion_offensive_tool_keyword = /\/PerfusionDll\.dll/ nocase ascii wide
                        $string4_Perfusion_offensive_tool_keyword = /\[\!\]\sFailed\sto\sdelete\sPerformance\sregistry\skey\./ nocase ascii wide
                        $string5_Perfusion_offensive_tool_keyword = /\[\-\]\sFailed\sto\sdelete\sPerformance\sDLL/ nocase ascii wide
                        $string6_Perfusion_offensive_tool_keyword = /\[\+\]\sExploit\scompleted\.\sGot\sa\sSYSTEM\stoken\!\s\:\)/ nocase ascii wide
                        $string7_Perfusion_offensive_tool_keyword = /\\Perfusion\.cpp/ nocase ascii wide
                        $string8_Perfusion_offensive_tool_keyword = /\\Perfusion\.exe/ nocase ascii wide
                        $string9_Perfusion_offensive_tool_keyword = /\\Perfusion\.sln/ nocase ascii wide
                        $string10_Perfusion_offensive_tool_keyword = /\\PerfusionDll\.cpp/ nocase ascii wide
                        $string11_Perfusion_offensive_tool_keyword = /\\PerfusionDll\.dll/ nocase ascii wide
                        $string12_Perfusion_offensive_tool_keyword = /\\PerfusionDll\.log/ nocase ascii wide
                        $string13_Perfusion_offensive_tool_keyword = "1B1F64B3-B8A4-4BBB-BB66-F020E2D4F288" nocase ascii wide
                        $string14_Perfusion_offensive_tool_keyword = "A7397316-0AEF-4379-B285-C276DE02BDE1" nocase ascii wide
                        $string15_Perfusion_offensive_tool_keyword = /C\:\\Users\\.{0,1000}\\AppData\\Local\\Temp\\performance_636_3000_1\.dll/ nocase ascii wide
                        $string16_Perfusion_offensive_tool_keyword = /https\:\/\/itm4n\.github\.io\/windows\-registry\-rpceptmapper\-eop\// nocase ascii wide
                        $string17_Perfusion_offensive_tool_keyword = "itm4n/Perfusion" nocase ascii wide
                        $string18_Perfusion_offensive_tool_keyword = /Perfusion\.exe\s\-c/ nocase ascii wide
                        $string19_Perfusion_offensive_tool_keyword = /Perfusion\\RegistryPatch\.ps1/ nocase ascii wide
                        $string20_Perfusion_offensive_tool_keyword = /Perfusion\-master\.zip/ nocase ascii wide
                        $string21_Perfusion_offensive_tool_keyword = /WritePayloadDll\(LPWSTR\spwszDllPath\)/ nocase ascii wide

    condition:
        any of them
}