rule NimScan
{
    meta:
        description = "Detection patterns for the tool 'NimScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimScan"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sNimScan\.exe/ nocase ascii wide
                        $string2 = /\sNimScan\.nim/ nocase ascii wide
                        $string3 = /\/NimScan\.exe/ nocase ascii wide
                        $string4 = /\/NimScan\.git/ nocase ascii wide
                        $string5 = /\/NimScan\.nim/ nocase ascii wide
                        $string6 = /\\NimScan\.exe/ nocase ascii wide
                        $string7 = /\\NimScan\.nim/ nocase ascii wide
                        $string8 = ">NimScan<" nocase ascii wide
                        $string9 = "162b04e6c89653b10bd38def513051067393d9080afd777210b0ce44f1a7d9fe" nocase ascii wide
                        $string10 = "394daa8e246f41baa4f37b1721991248f003766f079e671b8e51794259818c91" nocase ascii wide
                        $string11 = "662d9dd3a88b004a8eb3e5944457a1661ec7a28dd4695d6f96fbcbf095ba057a" nocase ascii wide
                        $string12 = "72605e93bf880f32e23eb3b5d1ab30a66c7a2beb3c195d5d2bc5738e1b7ddbf5" nocase ascii wide
                        $string13 = "9084acb8a61d051af66cad27ceb81976c45c4378e9846a22d8befe3294217e7d" nocase ascii wide
                        $string14 = "b6911a2d3730f3bbcd89d503ac1226d6e6172cb49d3c92d04df933ef3c9e1531" nocase ascii wide
                        $string15 = "ca96a1f8836f1c1afdf2c410e9d686f7beca7784e859971a493a6610522708e2" nocase ascii wide
                        $string16 = "dacdb4976fd75ab2fd7bb22f1b2f9d986f5d92c29555ce2b165c020e2816a200" nocase ascii wide
                        $string17 = "e43d66b7a4fa09a0714c573fbe4996770d9d85e31912480e73344124017098f9" nocase ascii wide
                        $string18 = "elddy/NimScan" nocase ascii wide
                        $string19 = /\-l\:NimScanToC\.a\s/ nocase ascii wide
                        $string20 = "netsh advfirewall firewall add rule name='NimScan'" nocase ascii wide
                        $string21 = /NimScan\s.{0,1000}\s\-p\:/ nocase ascii wide
                        $string22 = "NimScan finished in:" nocase ascii wide

    condition:
        any of them
}