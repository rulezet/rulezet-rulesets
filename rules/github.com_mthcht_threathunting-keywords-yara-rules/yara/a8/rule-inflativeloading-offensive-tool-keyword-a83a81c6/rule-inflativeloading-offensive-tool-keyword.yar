rule rule_InflativeLoading_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'InflativeLoading' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "InflativeLoading"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_InflativeLoading_offensive_tool_keyword = /\sInflativeLoading\.py/ nocase ascii wide
                        $string2_InflativeLoading_offensive_tool_keyword = /\spsexec_merged\.bin/ nocase ascii wide
                        $string3_InflativeLoading_offensive_tool_keyword = /\sReadPEInMemory\.exe/ nocase ascii wide
                        $string4_InflativeLoading_offensive_tool_keyword = /\/InflativeLoading\.git/ nocase ascii wide
                        $string5_InflativeLoading_offensive_tool_keyword = /\/InflativeLoading\.py/ nocase ascii wide
                        $string6_InflativeLoading_offensive_tool_keyword = /\/InflativeLoading\-main\.zip/ nocase ascii wide
                        $string7_InflativeLoading_offensive_tool_keyword = /\/mimikatz\.bin/ nocase ascii wide
                        $string8_InflativeLoading_offensive_tool_keyword = /\[\!\]\sPRESS\sTO\sEXECUTE\sSHELLCODED\sEXE/ nocase ascii wide
                        $string9_InflativeLoading_offensive_tool_keyword = /\[\!\]\sShellcoded\sPE\\\'s\ssize\:\s/ nocase ascii wide
                        $string10_InflativeLoading_offensive_tool_keyword = /\[\#\]\sShellcode\slocated\sat\saddress\s/ nocase ascii wide
                        $string11_InflativeLoading_offensive_tool_keyword = /\\DumpPEFromMemory\.sln/ nocase ascii wide
                        $string12_InflativeLoading_offensive_tool_keyword = /\\DumpPEFromMemory\.vcxproj/ nocase ascii wide
                        $string13_InflativeLoading_offensive_tool_keyword = /\\InflativeLoading\.py/ nocase ascii wide
                        $string14_InflativeLoading_offensive_tool_keyword = /\\InflativeLoading\\bin\\.{0,1000}\.bin/ nocase ascii wide
                        $string15_InflativeLoading_offensive_tool_keyword = /\\InflativeLoading\\bin\\.{0,1000}\.exe/ nocase ascii wide
                        $string16_InflativeLoading_offensive_tool_keyword = /\\InflativeLoading\-main\.zip/ nocase ascii wide
                        $string17_InflativeLoading_offensive_tool_keyword = /\\mimikatz\.bin/ nocase ascii wide
                        $string18_InflativeLoading_offensive_tool_keyword = /\\ReadPEInMemory\.exe/ nocase ascii wide
                        $string19_InflativeLoading_offensive_tool_keyword = /DumpPEFromMemory\.cpp/ nocase ascii wide
                        $string20_InflativeLoading_offensive_tool_keyword = /DumpPEFromMemory\.exe/ nocase ascii wide
                        $string21_InflativeLoading_offensive_tool_keyword = /DumpPEFromMemoryMemory\.exe/ nocase ascii wide
                        $string22_InflativeLoading_offensive_tool_keyword = "Dynamically convert a native PE to PIC shellcode" nocase ascii wide
                        $string23_InflativeLoading_offensive_tool_keyword = "EEC48565-5B42-491A-8BBB-16AC0C40C367" nocase ascii wide
                        $string24_InflativeLoading_offensive_tool_keyword = "Generated shellcode successfully saved in file " nocase ascii wide
                        $string25_InflativeLoading_offensive_tool_keyword = /InflativeLoading\.py\s/ nocase ascii wide
                        $string26_InflativeLoading_offensive_tool_keyword = "InflativeLoading-DumpPEFromMemory" nocase ascii wide
                        $string27_InflativeLoading_offensive_tool_keyword = "senzee1984/InflativeLoading" nocase ascii wide

    condition:
        any of them
}