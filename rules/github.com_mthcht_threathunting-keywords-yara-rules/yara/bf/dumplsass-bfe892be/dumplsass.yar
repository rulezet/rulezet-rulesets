rule DumpLSASS
{
    meta:
        description = "Detection patterns for the tool 'DumpLSASS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpLSASS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DumpLSASS\.git/ nocase ascii wide
                        $string2 = /\/MultiDump\.exe/ nocase ascii wide
                        $string3 = /\[\!\]\sDumping\sLSASS\sRequires\sElevated\sPriviledges\!/ nocase ascii wide
                        $string4 = /\[\!\]\sFailed\sto\sLocate\sLSASS\sDump\sFile\!/ nocase ascii wide
                        $string5 = /\[\+\]\sLSASS\sDump\sRead\:\s/ nocase ascii wide
                        $string6 = /\[i\]\sDumping\sLSASS\sUsing\s/ nocase ascii wide
                        $string7 = /\\a\\1\\s\\x64\\Release\\ProcDump64\.pdb/ nocase ascii wide
                        $string8 = /\\DumpLSASS\-main/ nocase ascii wide
                        $string9 = /\\MultiDump\.exe/ nocase ascii wide
                        $string10 = /\\Users\\Public\\lsass\.dmp/ nocase ascii wide
                        $string11 = /DumpLSASS\-main\.zip/ nocase ascii wide
                        $string12 = "elementalsouls/DumpLSASS" nocase ascii wide
                        $string13 = "f150333a3943f2c7398e0dd3f97a2cb3f1c1653a220785a977ba9a7ff692dab1" nocase ascii wide
                        $string14 = /Users\\\\Public\\\\lsass\.dmp/ nocase ascii wide

    condition:
        any of them
}