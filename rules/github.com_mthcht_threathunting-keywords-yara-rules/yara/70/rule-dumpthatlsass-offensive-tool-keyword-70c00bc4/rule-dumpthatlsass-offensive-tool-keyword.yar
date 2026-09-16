rule rule_DumpThatLSASS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DumpThatLSASS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpThatLSASS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DumpThatLSASS_offensive_tool_keyword = /\s1\$a\$\$\.exe/ nocase ascii wide
                        $string2_DumpThatLSASS_offensive_tool_keyword = /\sl\$a\$\$Pid\s/ nocase ascii wide
                        $string3_DumpThatLSASS_offensive_tool_keyword = /\/1\$a\$\$\.exe/ nocase ascii wide
                        $string4_DumpThatLSASS_offensive_tool_keyword = /\/DumpThatLSASS\./ nocase ascii wide
                        $string5_DumpThatLSASS_offensive_tool_keyword = /\/DumpThatLSASS\.git/ nocase ascii wide
                        $string6_DumpThatLSASS_offensive_tool_keyword = "/DumpThatLSASS/" nocase ascii wide
                        $string7_DumpThatLSASS_offensive_tool_keyword = /\[\+\]\sThe\s1\$a\$\$\.exe/ nocase ascii wide
                        $string8_DumpThatLSASS_offensive_tool_keyword = /\\1\$a\$\$\.exe/ nocase ascii wide
                        $string9_DumpThatLSASS_offensive_tool_keyword = /\\DumpThatLSASS\./ nocase ascii wide
                        $string10_DumpThatLSASS_offensive_tool_keyword = /\\DumpThatLSASS\\/ nocase ascii wide
                        $string11_DumpThatLSASS_offensive_tool_keyword = /\\sysDb\-dmp/ nocase ascii wide
                        $string12_DumpThatLSASS_offensive_tool_keyword = /1\$a\$\$\sDl_lmp\sin\s/ nocase ascii wide
                        $string13_DumpThatLSASS_offensive_tool_keyword = "1ebee3f2cc0a98db23a6bf0af4e5dd14bd8d21a4de9cbba58d43521b0bbe1294" nocase ascii wide
                        $string14_DumpThatLSASS_offensive_tool_keyword = "64D84D51-F462-4A24-85EA-845C97238C09" nocase ascii wide
                        $string15_DumpThatLSASS_offensive_tool_keyword = "952c94381c139e9d0b212d7f854ad261827e6694eac3e17b2c606ff9f54a7e91" nocase ascii wide
                        $string16_DumpThatLSASS_offensive_tool_keyword = "Failed in m1n1dumpIT:" nocase ascii wide
                        $string17_DumpThatLSASS_offensive_tool_keyword = /\'l\'\,\'s\'\,\'a\'\,\'s\'\,\'s\'\,\'\.\'\,\'e\'\,\'x\'\,\'e\'/ nocase ascii wide
                        $string18_DumpThatLSASS_offensive_tool_keyword = "'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p'" nocase ascii wide
                        $string19_DumpThatLSASS_offensive_tool_keyword = "peiga/DumpThatLSASS" nocase ascii wide
                        $string20_DumpThatLSASS_offensive_tool_keyword = "'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e'" nocase ascii wide
                        $string21_DumpThatLSASS_offensive_tool_keyword = /\'W\'\,\'i\'\,\'n\'\,\'d\'\,\'o\'\,\'w\'\,\'s\'\,\'\\\\\'\,\'S\'\,\'y\'\,\'s\'\,\'t\'\,\'e\'\,\'m\'\,\'3\'\,\'2\'/ nocase ascii wide

    condition:
        any of them
}