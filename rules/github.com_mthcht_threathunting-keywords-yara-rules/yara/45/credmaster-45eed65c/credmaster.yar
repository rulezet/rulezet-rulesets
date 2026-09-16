rule CredMaster
{
    meta:
        description = "Detection patterns for the tool 'CredMaster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CredMaster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --weekday-warrior -" nocase ascii wide
                        $string2 = /\scredmaster\.py/ nocase ascii wide
                        $string3 = /\scredmaster\-success\.txt/ nocase ascii wide
                        $string4 = /\scredmaster\-validusers\.txt/ nocase ascii wide
                        $string5 = /\sntlmdecoder\.py/ nocase ascii wide
                        $string6 = /\soh365userfinder\.py/ nocase ascii wide
                        $string7 = " --passwordsperdelay " nocase ascii wide
                        $string8 = " --plugin gmailenum" nocase ascii wide
                        $string9 = " --plugin httpbrute --url " nocase ascii wide
                        $string10 = " --plugin httpbrute" nocase ascii wide
                        $string11 = " --plugin o365enum" nocase ascii wide
                        $string12 = /\sutils\.ntlmdecode\s/ nocase ascii wide
                        $string13 = /\/CredMaster\.git/ nocase ascii wide
                        $string14 = /\/credmaster\.py/ nocase ascii wide
                        $string15 = /\/credmaster\.txt/
                        $string16 = /\/CredMaster\-master\.zip/ nocase ascii wide
                        $string17 = /\/credmaster\-success\.txt/
                        $string18 = /\/credmaster\-validusers\.txt/
                        $string19 = /\/ntlmdecoder\.py/ nocase ascii wide
                        $string20 = /\/oh365userfinder\.py/ nocase ascii wide
                        $string21 = /\\credmaster\.py/ nocase ascii wide
                        $string22 = /\\credmaster\.txt/ nocase ascii wide
                        $string23 = /\\CredMaster\-master\.zip/ nocase ascii wide
                        $string24 = /\\credmaster\-success\.txt/ nocase ascii wide
                        $string25 = /\\credmaster\-validusers\.txt/ nocase ascii wide
                        $string26 = /\\ntlmdecoder\.py/ nocase ascii wide
                        $string27 = /\\oh365userfinder\.py/ nocase ascii wide
                        $string28 = "05f4184029b94e304fcef2f2c6875c1fb2a226f0d94fce013643727b10b169a5" nocase ascii wide
                        $string29 = "4665bf3f84b00ec83f005ea4feb3617acf032a69826013656a04683865c204f6" nocase ascii wide
                        $string30 = "48dd94df199f63a06b571290ca42e17488f7053605449341eb9747807a26aa10" nocase ascii wide
                        $string31 = "4aa1f8595b2334131d7349d8e60ed3d0bfe9c72abd053d42b6e74111b4e010eb" nocase ascii wide
                        $string32 = "7bc64714fb90bddef226c04fb69f30d689384e3f0dfb89934c73ad1486e76e3a" nocase ascii wide
                        $string33 = "a32580495d4c71174e41935bf681c053aef15993a80c663f224790588b713742" nocase ascii wide
                        $string34 = "acc6cd307e1dd184b722a082c177639e78421f79b0e3b26fa602f1ce8392cc4f" nocase ascii wide
                        $string35 = /credmaster\.py\s/ nocase ascii wide
                        $string36 = /CredMaster\\passwords\.txt/ nocase ascii wide
                        $string37 = "docker build -t credmaster" nocase ascii wide
                        $string38 = /httpbrute\.py/ nocase ascii wide
                        $string39 = "knavesec/CredMaster" nocase ascii wide
                        $string40 = /ntlmdecoder\.py/ nocase ascii wide
                        $string41 = /o365enum\.py/ nocase ascii wide
                        $string42 = /oh365userfinder\.py/ nocase ascii wide
                        $string43 = "PassSpray: Valid Credentials Obtained!" nocase ascii wide
                        $string44 = /tester12345678\@gmail\.com/ nocase ascii wide

    condition:
        any of them
}