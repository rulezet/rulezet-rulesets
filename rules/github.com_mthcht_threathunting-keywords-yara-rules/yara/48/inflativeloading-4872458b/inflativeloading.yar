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
                        $string14 = /\\InflativeLoading\\bin\\.{0,100}\.bin/ nocase ascii wide
                        $string15 = /\\InflativeLoading\\bin\\.{0,100}\.exe/ nocase ascii wide
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