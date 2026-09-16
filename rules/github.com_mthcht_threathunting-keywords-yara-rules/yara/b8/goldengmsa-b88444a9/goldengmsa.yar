rule GoldenGMSA
{
    meta:
        description = "Detection patterns for the tool 'GoldenGMSA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoldenGMSA"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\scompute\s\-\-sid\s.{0,1000}\s\-\-kdskey\s/ nocase ascii wide
                        $string2 = /\.exe\sgmsainfo\s\-\-sid\s/ nocase ascii wide
                        $string3 = /\.exe\skdsinfo\s\-\-guid\s/ nocase ascii wide
                        $string4 = /\/GoldenGMSA\.git/ nocase ascii wide
                        $string5 = /GoldenGMSA\.exe/ nocase ascii wide
                        $string6 = "GoldenGMSA-main" nocase ascii wide
                        $string7 = "Semperis/GoldenGMSA" nocase ascii wide

    condition:
        any of them
}