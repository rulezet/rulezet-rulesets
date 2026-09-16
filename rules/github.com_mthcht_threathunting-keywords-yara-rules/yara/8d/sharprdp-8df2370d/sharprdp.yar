rule SharpRDP
{
    meta:
        description = "Detection patterns for the tool 'SharpRDP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRDP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Execute command elevated through Run Dialog" nocase ascii wide
                        $string2 = " Execute command elevated through task manager" nocase ascii wide
                        $string3 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\snla\=true/ nocase ascii wide
                        $string4 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\stakeover\=true/ nocase ascii wide
                        $string5 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\sconnectdrive\=true/ nocase ascii wide
                        $string6 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\selevated\=taskmgr/ nocase ascii wide
                        $string7 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\selevated\=winr/ nocase ascii wide
                        $string8 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\sexec\=cmd/ nocase ascii wide
                        $string9 = /\.WriteLine\(\\"SharpRDP\\"\)/ nocase ascii wide
                        $string10 = /\/SharpRDP\.exe/ nocase ascii wide
                        $string11 = /\/SharpRDP\.git/ nocase ascii wide
                        $string12 = /\\SharpRDP\.exe/ nocase ascii wide
                        $string13 = /\\SharpRDP\.pdb/ nocase ascii wide
                        $string14 = /\\SharpRDP\\/ nocase ascii wide
                        $string15 = ">SharpRDP<" nocase ascii wide
                        $string16 = "0xthirteen/SharpRDP" nocase ascii wide
                        $string17 = /Ask\sto\stake\sover\sRDP\ssession\sif\sanother\sused\sis\slogged\sin\s\(workstation\)/ nocase ascii wide
                        $string18 = "b4726b5d0aa21ed0f06326fcf2f9bd0c6171c76b610287a357710174f06dea52" nocase ascii wide
                        $string19 = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" nocase ascii wide
                        $string20 = /SharpRDP\..{0,1000}\.dll\.bin/ nocase ascii wide
                        $string21 = /SharpRDP\.csproj/ nocase ascii wide
                        $string22 = /SharpRDP\.exe/ nocase ascii wide
                        $string23 = /SharpRDP\.sln/ nocase ascii wide
                        $string24 = "SharpRDP-master" nocase ascii wide

    condition:
        any of them
}