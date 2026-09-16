rule Dumpy
{
    meta:
        description = "Detection patterns for the tool 'Dumpy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dumpy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\s\-\-dump\s\-k\s.{0,1000}\s\-u\shttp/ nocase ascii wide
                        $string2 = /\/dumpy\.exe/ nocase ascii wide
                        $string3 = /\/Dumpy\.git/ nocase ascii wide
                        $string4 = /\[\!\]\sLsass\sdump\screated\!/ nocase ascii wide
                        $string5 = /\[\+\]\sSuccessfully\sdecrypted\sminidump\sfile/ nocase ascii wide
                        $string6 = /\\dumpy\.exe/ nocase ascii wide
                        $string7 = "7876ba8fb2f4a1e4802f1f2c1030b9bc708f3981264fea33e261be7e05966169" nocase ascii wide
                        $string8 = /dumpy\.exe\s\-\-dump/ nocase ascii wide
                        $string9 = "Kudaes/Dumpy" nocase ascii wide

    condition:
        any of them
}