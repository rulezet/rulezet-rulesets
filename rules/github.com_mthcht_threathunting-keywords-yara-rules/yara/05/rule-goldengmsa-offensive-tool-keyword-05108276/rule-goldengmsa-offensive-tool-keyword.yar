rule rule_GoldenGMSA_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GoldenGMSA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoldenGMSA"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GoldenGMSA_offensive_tool_keyword = /\.exe\scompute\s\-\-sid\s.{0,1000}\s\-\-kdskey\s/ nocase ascii wide
                        $string2_GoldenGMSA_offensive_tool_keyword = /\.exe\sgmsainfo\s\-\-sid\s/ nocase ascii wide
                        $string3_GoldenGMSA_offensive_tool_keyword = /\.exe\skdsinfo\s\-\-guid\s/ nocase ascii wide
                        $string4_GoldenGMSA_offensive_tool_keyword = /\/GoldenGMSA\.git/ nocase ascii wide
                        $string5_GoldenGMSA_offensive_tool_keyword = /GoldenGMSA\.exe/ nocase ascii wide
                        $string6_GoldenGMSA_offensive_tool_keyword = "GoldenGMSA-main" nocase ascii wide
                        $string7_GoldenGMSA_offensive_tool_keyword = "Semperis/GoldenGMSA" nocase ascii wide

    condition:
        any of them
}