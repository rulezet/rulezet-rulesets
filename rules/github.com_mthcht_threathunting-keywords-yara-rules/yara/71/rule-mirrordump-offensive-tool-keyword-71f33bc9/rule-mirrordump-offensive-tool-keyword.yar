rule rule_MirrorDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MirrorDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MirrorDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MirrorDump_offensive_tool_keyword = /\sMirrorDump\.exe/ nocase ascii wide
                        $string2_MirrorDump_offensive_tool_keyword = /\/lsass\.rar/ nocase ascii wide
                        $string3_MirrorDump_offensive_tool_keyword = /\/lsass\.zip/ nocase ascii wide
                        $string4_MirrorDump_offensive_tool_keyword = /\/MirrorDump\.exe/ nocase ascii wide
                        $string5_MirrorDump_offensive_tool_keyword = /\/MirrorDump\.git/ nocase ascii wide
                        $string6_MirrorDump_offensive_tool_keyword = /\[\!\]\sFailed\sto\sfake\sNtOpenProcess\son\sLSASS\sPID/ nocase ascii wide
                        $string7_MirrorDump_offensive_tool_keyword = /\[\!\]\sFailed\sto\sget\sLSASS\shandle\,\sbailing\!/ nocase ascii wide
                        $string8_MirrorDump_offensive_tool_keyword = /\[\+\]\sMinidump\ssuccessfully\ssaved\sto\smemory/ nocase ascii wide
                        $string9_MirrorDump_offensive_tool_keyword = /\[\=\]\sDumping\sLSASS\smemory/ nocase ascii wide
                        $string10_MirrorDump_offensive_tool_keyword = /\\lsass\.rar/ nocase ascii wide
                        $string11_MirrorDump_offensive_tool_keyword = /\\lsass\.zip/ nocase ascii wide
                        $string12_MirrorDump_offensive_tool_keyword = /\\MiniDumpToMem\.cs/ nocase ascii wide
                        $string13_MirrorDump_offensive_tool_keyword = /\\MirrorDump\.csproj/ nocase ascii wide
                        $string14_MirrorDump_offensive_tool_keyword = /\\MirrorDump\.exe/ nocase ascii wide
                        $string15_MirrorDump_offensive_tool_keyword = /\\MirrorDump\.sln/ nocase ascii wide
                        $string16_MirrorDump_offensive_tool_keyword = /\\MirrorDump\\MinHook/ nocase ascii wide
                        $string17_MirrorDump_offensive_tool_keyword = /\\MirrorDump\\MiniDump\\/ nocase ascii wide
                        $string18_MirrorDump_offensive_tool_keyword = /\\MirrorDump\-master/ nocase ascii wide
                        $string19_MirrorDump_offensive_tool_keyword = "58338E42-6010-493C-B8C8-2FD2CFC30FFB" nocase ascii wide
                        $string20_MirrorDump_offensive_tool_keyword = "CCob/MirrorDump" nocase ascii wide
                        $string21_MirrorDump_offensive_tool_keyword = /minidumptomemsharp\.lsa\.lsaproviderduper\.boo/ nocase ascii wide
                        $string22_MirrorDump_offensive_tool_keyword = /NotLSASS\.zip/ nocase ascii wide
                        $string23_MirrorDump_offensive_tool_keyword = /NotLSASS1\.zip/ nocase ascii wide
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