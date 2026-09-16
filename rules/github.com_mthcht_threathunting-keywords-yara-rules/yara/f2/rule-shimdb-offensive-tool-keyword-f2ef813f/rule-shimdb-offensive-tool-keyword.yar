rule rule_ShimDB_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShimDB' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShimDB"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShimDB_offensive_tool_keyword = /\/sdb\-explorer\.exe/ nocase ascii wide
                        $string2_ShimDB_offensive_tool_keyword = /\/ShimDB\.git/ nocase ascii wide
                        $string3_ShimDB_offensive_tool_keyword = /\\sdb\-explorer\.exe/ nocase ascii wide
                        $string4_ShimDB_offensive_tool_keyword = /\\sdb\-explorer\.sln/ nocase ascii wide
                        $string5_ShimDB_offensive_tool_keyword = /\\ShimDB\\sdb\-explorer/ nocase ascii wide
                        $string6_ShimDB_offensive_tool_keyword = "223279bb628165de88609c81444f4a9bf9aac6f921ea155ac427a47d13b49084" nocase ascii wide
                        $string7_ShimDB_offensive_tool_keyword = "A1A949A4-5CE4-4FCF-A3B9-A2290EA46086" nocase ascii wide
                        $string8_ShimDB_offensive_tool_keyword = "jackson5sec/ShimDB" nocase ascii wide

    condition:
        any of them
}