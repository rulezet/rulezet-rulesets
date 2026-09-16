rule Perfusion
{
    meta:
        description = "Detection patterns for the tool 'Perfusion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Perfusion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Perfusion\.exe/ nocase ascii wide
                        $string2 = /\/Perfusion\.git/ nocase ascii wide
                        $string3 = /\/PerfusionDll\.dll/ nocase ascii wide
                        $string4 = /\[\!\]\sFailed\sto\sdelete\sPerformance\sregistry\skey\./ nocase ascii wide
                        $string5 = /\[\-\]\sFailed\sto\sdelete\sPerformance\sDLL/ nocase ascii wide
                        $string6 = /\[\+\]\sExploit\scompleted\.\sGot\sa\sSYSTEM\stoken\!\s\:\)/ nocase ascii wide
                        $string7 = /\\Perfusion\.cpp/ nocase ascii wide
                        $string8 = /\\Perfusion\.exe/ nocase ascii wide
                        $string9 = /\\Perfusion\.sln/ nocase ascii wide
                        $string10 = /\\PerfusionDll\.cpp/ nocase ascii wide
                        $string11 = /\\PerfusionDll\.dll/ nocase ascii wide
                        $string12 = /\\PerfusionDll\.log/ nocase ascii wide
                        $string13 = "1B1F64B3-B8A4-4BBB-BB66-F020E2D4F288" nocase ascii wide
                        $string14 = "A7397316-0AEF-4379-B285-C276DE02BDE1" nocase ascii wide
                        $string15 = /C\:\\Users\\.{0,1000}\\AppData\\Local\\Temp\\performance_636_3000_1\.dll/ nocase ascii wide
                        $string16 = /https\:\/\/itm4n\.github\.io\/windows\-registry\-rpceptmapper\-eop\// nocase ascii wide
                        $string17 = "itm4n/Perfusion" nocase ascii wide
                        $string18 = /Perfusion\.exe\s\-c/ nocase ascii wide
                        $string19 = /Perfusion\\RegistryPatch\.ps1/ nocase ascii wide
                        $string20 = /Perfusion\-master\.zip/ nocase ascii wide
                        $string21 = /WritePayloadDll\(LPWSTR\spwszDllPath\)/ nocase ascii wide

    condition:
        any of them
}