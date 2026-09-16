rule rule_Diamorphine_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Diamorphine' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Diamorphine"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Diamorphine_offensive_tool_keyword = /\sdiamorphine\.c/
                        $string2_Diamorphine_offensive_tool_keyword = /\sdiamorphine\.h/
                        $string3_Diamorphine_offensive_tool_keyword = " hacked_getdents"
                        $string4_Diamorphine_offensive_tool_keyword = /\/Diamorphine\.git/
                        $string5_Diamorphine_offensive_tool_keyword = /\\diamorphine\.c/
                        $string6_Diamorphine_offensive_tool_keyword = /\\diamorphine\.h/
                        $string7_Diamorphine_offensive_tool_keyword = "5d637915abc98b21f94b0648c552899af67321ab06fb34e33339ae38401734cf"
                        $string8_Diamorphine_offensive_tool_keyword = "b7b5637287f143fe5e54c022e6c7b785141cfdeec2aceac263ee38e5ac17d3d7"
                        $string9_Diamorphine_offensive_tool_keyword = "f0e1e5a2b52773889dc1e7c44c5a80716a0dd98beee46b705748773e292e1d88"
                        $string10_Diamorphine_offensive_tool_keyword = /hacked_getdents64\(/
                        $string11_Diamorphine_offensive_tool_keyword = /hacked_kill\(/
                        $string12_Diamorphine_offensive_tool_keyword = /LKM_HACKING\.html/
                        $string13_Diamorphine_offensive_tool_keyword = "m0nad/Diamorphine"
                        $string14_Diamorphine_offensive_tool_keyword = "MAGIC_PREFIX \"diamorphine_secret"
                        $string15_Diamorphine_offensive_tool_keyword = /MODULE_AUTHOR\(\\"m0nad\\"\)/
                        $string16_Diamorphine_offensive_tool_keyword = /MODULE_DESCRIPTION\(\\"LKM\srootkit\\"/
                        $string17_Diamorphine_offensive_tool_keyword = "MODULE_NAME \"diamorphine\""
                        $string18_Diamorphine_offensive_tool_keyword = "rmmod diamorphine"
                        $string19_Diamorphine_offensive_tool_keyword = /writing\-rootkit\.txt/

    condition:
        any of them
}