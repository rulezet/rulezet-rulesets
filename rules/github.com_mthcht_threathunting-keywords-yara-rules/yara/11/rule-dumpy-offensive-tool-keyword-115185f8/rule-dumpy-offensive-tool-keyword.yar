rule rule_Dumpy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Dumpy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dumpy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Dumpy_offensive_tool_keyword = /\.exe\s\-\-dump\s\-k\s.{0,1000}\s\-u\shttp/ nocase ascii wide
                        $string2_Dumpy_offensive_tool_keyword = /\/dumpy\.exe/ nocase ascii wide
                        $string3_Dumpy_offensive_tool_keyword = /\/Dumpy\.git/ nocase ascii wide
                        $string4_Dumpy_offensive_tool_keyword = /\[\!\]\sLsass\sdump\screated\!/ nocase ascii wide
                        $string5_Dumpy_offensive_tool_keyword = /\[\+\]\sSuccessfully\sdecrypted\sminidump\sfile/ nocase ascii wide
                        $string6_Dumpy_offensive_tool_keyword = /\\dumpy\.exe/ nocase ascii wide
                        $string7_Dumpy_offensive_tool_keyword = "7876ba8fb2f4a1e4802f1f2c1030b9bc708f3981264fea33e261be7e05966169" nocase ascii wide
                        $string8_Dumpy_offensive_tool_keyword = /dumpy\.exe\s\-\-dump/ nocase ascii wide
                        $string9_Dumpy_offensive_tool_keyword = "Kudaes/Dumpy" nocase ascii wide

    condition:
        any of them
}