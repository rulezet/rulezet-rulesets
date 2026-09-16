rule rule_CredMaster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CredMaster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CredMaster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CredMaster_offensive_tool_keyword = " --weekday-warrior -" nocase ascii wide
                        $string2_CredMaster_offensive_tool_keyword = /\scredmaster\.py/ nocase ascii wide
                        $string3_CredMaster_offensive_tool_keyword = /\scredmaster\-success\.txt/ nocase ascii wide
                        $string4_CredMaster_offensive_tool_keyword = /\scredmaster\-validusers\.txt/ nocase ascii wide
                        $string5_CredMaster_offensive_tool_keyword = /\sntlmdecoder\.py/ nocase ascii wide
                        $string6_CredMaster_offensive_tool_keyword = /\soh365userfinder\.py/ nocase ascii wide
                        $string7_CredMaster_offensive_tool_keyword = " --passwordsperdelay " nocase ascii wide
                        $string8_CredMaster_offensive_tool_keyword = " --plugin gmailenum" nocase ascii wide
                        $string9_CredMaster_offensive_tool_keyword = " --plugin httpbrute --url " nocase ascii wide
                        $string10_CredMaster_offensive_tool_keyword = " --plugin httpbrute" nocase ascii wide
                        $string11_CredMaster_offensive_tool_keyword = " --plugin o365enum" nocase ascii wide
                        $string12_CredMaster_offensive_tool_keyword = /\sutils\.ntlmdecode\s/ nocase ascii wide
                        $string13_CredMaster_offensive_tool_keyword = /\/CredMaster\.git/ nocase ascii wide
                        $string14_CredMaster_offensive_tool_keyword = /\/credmaster\.py/ nocase ascii wide
                        $string15_CredMaster_offensive_tool_keyword = /\/credmaster\.txt/
                        $string16_CredMaster_offensive_tool_keyword = /\/CredMaster\-master\.zip/ nocase ascii wide
                        $string17_CredMaster_offensive_tool_keyword = /\/credmaster\-success\.txt/
                        $string18_CredMaster_offensive_tool_keyword = /\/credmaster\-validusers\.txt/
                        $string19_CredMaster_offensive_tool_keyword = /\/ntlmdecoder\.py/ nocase ascii wide
                        $string20_CredMaster_offensive_tool_keyword = /\/oh365userfinder\.py/ nocase ascii wide
                        $string21_CredMaster_offensive_tool_keyword = /\\credmaster\.py/ nocase ascii wide
                        $string22_CredMaster_offensive_tool_keyword = /\\credmaster\.txt/ nocase ascii wide
                        $string23_CredMaster_offensive_tool_keyword = /\\CredMaster\-master\.zip/ nocase ascii wide
                        $string24_CredMaster_offensive_tool_keyword = /\\credmaster\-success\.txt/ nocase ascii wide
                        $string25_CredMaster_offensive_tool_keyword = /\\credmaster\-validusers\.txt/ nocase ascii wide
                        $string26_CredMaster_offensive_tool_keyword = /\\ntlmdecoder\.py/ nocase ascii wide
                        $string27_CredMaster_offensive_tool_keyword = /\\oh365userfinder\.py/ nocase ascii wide
                        $string28_CredMaster_offensive_tool_keyword = "05f4184029b94e304fcef2f2c6875c1fb2a226f0d94fce013643727b10b169a5" nocase ascii wide
                        $string29_CredMaster_offensive_tool_keyword = "4665bf3f84b00ec83f005ea4feb3617acf032a69826013656a04683865c204f6" nocase ascii wide
                        $string30_CredMaster_offensive_tool_keyword = "48dd94df199f63a06b571290ca42e17488f7053605449341eb9747807a26aa10" nocase ascii wide
                        $string31_CredMaster_offensive_tool_keyword = "4aa1f8595b2334131d7349d8e60ed3d0bfe9c72abd053d42b6e74111b4e010eb" nocase ascii wide
                        $string32_CredMaster_offensive_tool_keyword = "7bc64714fb90bddef226c04fb69f30d689384e3f0dfb89934c73ad1486e76e3a" nocase ascii wide
                        $string33_CredMaster_offensive_tool_keyword = "a32580495d4c71174e41935bf681c053aef15993a80c663f224790588b713742" nocase ascii wide
                        $string34_CredMaster_offensive_tool_keyword = "acc6cd307e1dd184b722a082c177639e78421f79b0e3b26fa602f1ce8392cc4f" nocase ascii wide
                        $string35_CredMaster_offensive_tool_keyword = /credmaster\.py\s/ nocase ascii wide
                        $string36_CredMaster_offensive_tool_keyword = /CredMaster\\passwords\.txt/ nocase ascii wide
                        $string37_CredMaster_offensive_tool_keyword = "docker build -t credmaster" nocase ascii wide
                        $string38_CredMaster_offensive_tool_keyword = /httpbrute\.py/ nocase ascii wide
                        $string39_CredMaster_offensive_tool_keyword = "knavesec/CredMaster" nocase ascii wide
                        $string40_CredMaster_offensive_tool_keyword = /ntlmdecoder\.py/ nocase ascii wide
                        $string41_CredMaster_offensive_tool_keyword = /o365enum\.py/ nocase ascii wide
                        $string42_CredMaster_offensive_tool_keyword = /oh365userfinder\.py/ nocase ascii wide
                        $string43_CredMaster_offensive_tool_keyword = "PassSpray: Valid Credentials Obtained!" nocase ascii wide
                        $string44_CredMaster_offensive_tool_keyword = /tester12345678\@gmail\.com/ nocase ascii wide

    condition:
        any of them
}