rule rule_JuicyPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'JuicyPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JuicyPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_JuicyPotato_offensive_tool_keyword = /\/JuicyPotato\.exe/ nocase ascii wide
                        $string2_JuicyPotato_offensive_tool_keyword = /\/JuicyPotato\.git/ nocase ascii wide
                        $string3_JuicyPotato_offensive_tool_keyword = /\/JuicyPotato_x32\.exe/ nocase ascii wide
                        $string4_JuicyPotato_offensive_tool_keyword = /\/JuicyPotato_x64\.exe/ nocase ascii wide
                        $string5_JuicyPotato_offensive_tool_keyword = "/JuicyPotato-webshell/" nocase ascii wide
                        $string6_JuicyPotato_offensive_tool_keyword = /\\JuicyPotato\.exe/ nocase ascii wide
                        $string7_JuicyPotato_offensive_tool_keyword = /\\JuicyPotato\.pdb/ nocase ascii wide
                        $string8_JuicyPotato_offensive_tool_keyword = /\\JuicyPotato\.pdb/ nocase ascii wide
                        $string9_JuicyPotato_offensive_tool_keyword = /\\JuicyPotato_x32\.exe/ nocase ascii wide
                        $string10_JuicyPotato_offensive_tool_keyword = /\\JuicyPotato_x64\.exe/ nocase ascii wide
                        $string11_JuicyPotato_offensive_tool_keyword = /\\JuicyPotato\-master/ nocase ascii wide
                        $string12_JuicyPotato_offensive_tool_keyword = /\\JuicyPotato\-shellcode\\/ nocase ascii wide
                        $string13_JuicyPotato_offensive_tool_keyword = /\]\sQueueUserAPC\sInject\sshellcode\scompleted\,\senjoy\!/ nocase ascii wide
                        $string14_JuicyPotato_offensive_tool_keyword = "0212bde3715a349a6b684dd54548638b5899be8d62a1e25559937e494e3cce54" nocase ascii wide
                        $string15_JuicyPotato_offensive_tool_keyword = "02cbcc3c3b79a7f81165838af0605d7238e8c5ad7a6e2d59d7795c1f137fe7a4" nocase ascii wide
                        $string16_JuicyPotato_offensive_tool_keyword = "050dcd051a109b6bd8804e769242ec4e1c087bdd2fb45880c2affeebb630cf77" nocase ascii wide
                        $string17_JuicyPotato_offensive_tool_keyword = "1141183bf4a5fdb8a92a4bb9ae2278ec6391e1bc96ebee10245ad8a416372bd9" nocase ascii wide
                        $string18_JuicyPotato_offensive_tool_keyword = "1141183bf4a5fdb8a92a4bb9ae2278ec6391e1bc96ebee10245ad8a416372bd9" nocase ascii wide
                        $string19_JuicyPotato_offensive_tool_keyword = "146ca286f362290e96eda2a0b7cd9feb4e971763ba194731d1826e12e593439d" nocase ascii wide
                        $string20_JuicyPotato_offensive_tool_keyword = "4164003E-BA47-4A95-8586-D5AAC399C050" nocase ascii wide
                        $string21_JuicyPotato_offensive_tool_keyword = "86b4924004cdef5e49cdc9ca7cbd2d8be156b8e8f41eceee92492cc315103eb8" nocase ascii wide
                        $string22_JuicyPotato_offensive_tool_keyword = "f0761ad307781bdf8da94765abd1a2041ac12a52c7fdde85f00b2b2cab6d6ce8" nocase ascii wide
                        $string23_JuicyPotato_offensive_tool_keyword = "f8c05d66a6fda535ef4e8e767c8e3ca5c93a0828ff03498b4b6cbe7e39bb617b" nocase ascii wide
                        $string24_JuicyPotato_offensive_tool_keyword = "f8c05d66a6fda535ef4e8e767c8e3ca5c93a0828ff03498b4b6cbe7e39bb617b" nocase ascii wide
                        $string25_JuicyPotato_offensive_tool_keyword = "fd0b9f09770685ed6f40ecabcd31bc467fa22801164b52fdc638334009b7c06f" nocase ascii wide
                        $string26_JuicyPotato_offensive_tool_keyword = "JuicyPotato v%s" nocase ascii wide
                        $string27_JuicyPotato_offensive_tool_keyword = /JuicyPotato\.exe/ nocase ascii wide
                        $string28_JuicyPotato_offensive_tool_keyword = "Modifying JuciyPotato by Uknow to support webshell" nocase ascii wide
                        $string29_JuicyPotato_offensive_tool_keyword = /MSFRottenPotatoTestHarness\.exe/ nocase ascii wide
                        $string30_JuicyPotato_offensive_tool_keyword = "uknowsec/JuicyPotato" nocase ascii wide
                        $string31_JuicyPotato_offensive_tool_keyword = /x64\\Debug\\JuicyPotato/ nocase ascii wide
                        $string32_JuicyPotato_offensive_tool_keyword = /x64\\Release\\JuicyPotato/ nocase ascii wide

    condition:
        any of them
}