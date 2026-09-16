rule InflativeLoading
{
    meta:
        description = "Detection patterns for the tool 'InflativeLoading' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "InflativeLoading"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sInflativeLoading\.py/ nocase ascii wide
                        $string2 = /\spsexec_merged\.bin/ nocase ascii wide
                        $string3 = /\sReadPEInMemory\.exe/ nocase ascii wide
                        $string4 = /\/InflativeLoading\.git/ nocase ascii wide
                        $string5 = /\/InflativeLoading\.py/ nocase ascii wide
                        $string6 = /\/InflativeLoading\-main\.zip/ nocase ascii wide
                        $string7 = /\/mimikatz\.bin/ nocase ascii wide
                        $string8 = /\[\!\]\sPRESS\sTO\sEXECUTE\sSHELLCODED\sEXE/ nocase ascii wide
                        $string9 = /\[\!\]\sShellcoded\sPE\\\'s\ssize\:\s/ nocase ascii wide
                        $string10 = /\[\#\]\sShellcode\slocated\sat\saddress\s/ nocase ascii wide
                        $string11 = /\\DumpPEFromMemory\.sln/ nocase ascii wide
                        $string12 = /\\DumpPEFromMemory\.vcxproj/ nocase ascii wide
                        $string13 = /\\InflativeLoading\.py/ nocase ascii wide
                        $string14 = /\\InflativeLoading\\bin\\.{0,1000}\.bin/ nocase ascii wide
                        $string15 = /\\InflativeLoading\\bin\\.{0,1000}\.exe/ nocase ascii wide
                        $string16 = /\\InflativeLoading\-main\.zip/ nocase ascii wide
                        $string17 = /\\mimikatz\.bin/ nocase ascii wide
                        $string18 = /\\ReadPEInMemory\.exe/ nocase ascii wide
                        $string19 = /DumpPEFromMemory\.cpp/ nocase ascii wide
                        $string20 = /DumpPEFromMemory\.exe/ nocase ascii wide
                        $string21 = /DumpPEFromMemoryMemory\.exe/ nocase ascii wide
                        $string22 = "Dynamically convert a native PE to PIC shellcode" nocase ascii wide
                        $string23 = "EEC48565-5B42-491A-8BBB-16AC0C40C367" nocase ascii wide
                        $string24 = "Generated shellcode successfully saved in file " nocase ascii wide
                        $string25 = /InflativeLoading\.py\s/ nocase ascii wide
                        $string26 = "InflativeLoading-DumpPEFromMemory" nocase ascii wide
                        $string27 = "senzee1984/InflativeLoading" nocase ascii wide

    condition:
        any of them
}