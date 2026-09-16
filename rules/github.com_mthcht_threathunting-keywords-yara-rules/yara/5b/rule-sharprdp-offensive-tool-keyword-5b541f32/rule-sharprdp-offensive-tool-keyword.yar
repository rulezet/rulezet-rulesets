rule rule_SharpRDP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpRDP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRDP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpRDP_offensive_tool_keyword = " Execute command elevated through Run Dialog" nocase ascii wide
                        $string2_SharpRDP_offensive_tool_keyword = " Execute command elevated through task manager" nocase ascii wide
                        $string3_SharpRDP_offensive_tool_keyword = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\snla\=true/ nocase ascii wide
                        $string4_SharpRDP_offensive_tool_keyword = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\stakeover\=true/ nocase ascii wide
                        $string5_SharpRDP_offensive_tool_keyword = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\sconnectdrive\=true/ nocase ascii wide
                        $string6_SharpRDP_offensive_tool_keyword = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\selevated\=taskmgr/ nocase ascii wide
                        $string7_SharpRDP_offensive_tool_keyword = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\selevated\=winr/ nocase ascii wide
                        $string8_SharpRDP_offensive_tool_keyword = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\sexec\=cmd/ nocase ascii wide
                        $string9_SharpRDP_offensive_tool_keyword = /\.WriteLine\(\\"SharpRDP\\"\)/ nocase ascii wide
                        $string10_SharpRDP_offensive_tool_keyword = /\/SharpRDP\.exe/ nocase ascii wide
                        $string11_SharpRDP_offensive_tool_keyword = /\/SharpRDP\.git/ nocase ascii wide
                        $string12_SharpRDP_offensive_tool_keyword = /\\SharpRDP\.exe/ nocase ascii wide
                        $string13_SharpRDP_offensive_tool_keyword = /\\SharpRDP\.pdb/ nocase ascii wide
                        $string14_SharpRDP_offensive_tool_keyword = /\\SharpRDP\\/ nocase ascii wide
                        $string15_SharpRDP_offensive_tool_keyword = ">SharpRDP<" nocase ascii wide
                        $string16_SharpRDP_offensive_tool_keyword = "0xthirteen/SharpRDP" nocase ascii wide
                        $string17_SharpRDP_offensive_tool_keyword = /Ask\sto\stake\sover\sRDP\ssession\sif\sanother\sused\sis\slogged\sin\s\(workstation\)/ nocase ascii wide
                        $string18_SharpRDP_offensive_tool_keyword = "b4726b5d0aa21ed0f06326fcf2f9bd0c6171c76b610287a357710174f06dea52" nocase ascii wide
                        $string19_SharpRDP_offensive_tool_keyword = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" nocase ascii wide
                        $string20_SharpRDP_offensive_tool_keyword = /SharpRDP\..{0,1000}\.dll\.bin/ nocase ascii wide
                        $string21_SharpRDP_offensive_tool_keyword = /SharpRDP\.csproj/ nocase ascii wide
                        $string22_SharpRDP_offensive_tool_keyword = /SharpRDP\.exe/ nocase ascii wide
                        $string23_SharpRDP_offensive_tool_keyword = /SharpRDP\.sln/ nocase ascii wide
                        $string24_SharpRDP_offensive_tool_keyword = "SharpRDP-master" nocase ascii wide

    condition:
        any of them
}