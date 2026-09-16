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
                        $string15_Perfusion_offensive_tool_keyword = /C\:\\Users\\.{0,100}\\AppData\\Local\\Temp\\performance_636_3000_1\.dll/ nocase ascii wide
                        $string16_Perfusion_offensive_tool_keyword = /https\:\/\/itm4n\.github\.io\/windows\-registry\-rpceptmapper\-eop\// nocase ascii wide
                        $string17_Perfusion_offensive_tool_keyword = "itm4n/Perfusion" nocase ascii wide
                        $string18_Perfusion_offensive_tool_keyword = /Perfusion\.exe\s\-c/ nocase ascii wide
                        $string19_Perfusion_offensive_tool_keyword = /Perfusion\\RegistryPatch\.ps1/ nocase ascii wide
                        $string20_Perfusion_offensive_tool_keyword = /Perfusion\-master\.zip/ nocase ascii wide
                        $string21_Perfusion_offensive_tool_keyword = /WritePayloadDll\(LPWSTR\spwszDllPath\)/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}