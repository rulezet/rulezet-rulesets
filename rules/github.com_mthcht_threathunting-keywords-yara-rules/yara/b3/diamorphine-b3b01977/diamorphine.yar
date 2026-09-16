rule Diamorphine
{
    meta:
        description = "Detection patterns for the tool 'Diamorphine' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Diamorphine"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdiamorphine\.c/
                        $string2 = /\sdiamorphine\.h/
                        $string3 = " hacked_getdents"
                        $string4 = /\/Diamorphine\.git/
                        $string5 = /\\diamorphine\.c/
                        $string6 = /\\diamorphine\.h/
                        $string7 = "5d637915abc98b21f94b0648c552899af67321ab06fb34e33339ae38401734cf"
                        $string8 = "b7b5637287f143fe5e54c022e6c7b785141cfdeec2aceac263ee38e5ac17d3d7"
                        $string9 = "f0e1e5a2b52773889dc1e7c44c5a80716a0dd98beee46b705748773e292e1d88"
                        $string10 = /hacked_getdents64\(/
                        $string11 = /hacked_kill\(/
                        $string12 = /LKM_HACKING\.html/
                        $string13 = "m0nad/Diamorphine"
                        $string14 = "MAGIC_PREFIX \"diamorphine_secret"
                        $string15 = /MODULE_AUTHOR\(\\"m0nad\\"\)/
                        $string16 = /MODULE_DESCRIPTION\(\\"LKM\srootkit\\"/
                        $string17 = "MODULE_NAME \"diamorphine\""
                        $string18 = "rmmod diamorphine"
                        $string19 = /writing\-rootkit\.txt/

    condition:
        any of them
}