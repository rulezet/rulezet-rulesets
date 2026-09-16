rule MirrorDump
{
    meta:
        description = "Detection patterns for the tool 'MirrorDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MirrorDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sMirrorDump\.exe/ nocase ascii wide
                        $string2 = /\/lsass\.rar/ nocase ascii wide
                        $string3 = /\/lsass\.zip/ nocase ascii wide
                        $string4 = /\/MirrorDump\.exe/ nocase ascii wide
                        $string5 = /\/MirrorDump\.git/ nocase ascii wide
                        $string6 = /\[\!\]\sFailed\sto\sfake\sNtOpenProcess\son\sLSASS\sPID/ nocase ascii wide
                        $string7 = /\[\!\]\sFailed\sto\sget\sLSASS\shandle\,\sbailing\!/ nocase ascii wide
                        $string8 = /\[\+\]\sMinidump\ssuccessfully\ssaved\sto\smemory/ nocase ascii wide
                        $string9 = /\[\=\]\sDumping\sLSASS\smemory/ nocase ascii wide
                        $string10 = /\\lsass\.rar/ nocase ascii wide
                        $string11 = /\\lsass\.zip/ nocase ascii wide
                        $string12 = /\\MiniDumpToMem\.cs/ nocase ascii wide
                        $string13 = /\\MirrorDump\.csproj/ nocase ascii wide
                        $string14 = /\\MirrorDump\.exe/ nocase ascii wide
                        $string15 = /\\MirrorDump\.sln/ nocase ascii wide
                        $string16 = /\\MirrorDump\\MinHook/ nocase ascii wide
                        $string17 = /\\MirrorDump\\MiniDump\\/ nocase ascii wide
                        $string18 = /\\MirrorDump\-master/ nocase ascii wide
                        $string19 = "58338E42-6010-493C-B8C8-2FD2CFC30FFB" nocase ascii wide
                        $string20 = "CCob/MirrorDump" nocase ascii wide
                        $string21 = /minidumptomemsharp\.lsa\.lsaproviderduper\.boo/ nocase ascii wide
                        $string22 = /NotLSASS\.zip/ nocase ascii wide
                        $string23 = /NotLSASS1\.zip/ nocase ascii wide

    condition:
        any of them
}