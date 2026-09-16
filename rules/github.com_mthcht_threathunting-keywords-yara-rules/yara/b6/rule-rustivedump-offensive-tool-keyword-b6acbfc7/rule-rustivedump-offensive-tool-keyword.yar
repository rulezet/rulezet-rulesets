rule rule_RustiveDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RustiveDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustiveDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RustiveDump_offensive_tool_keyword = /\/RustiveDump\.exe/ nocase ascii wide
                        $string2_RustiveDump_offensive_tool_keyword = /\/RustiveDump\.git/ nocase ascii wide
                        $string3_RustiveDump_offensive_tool_keyword = /\[\+\]\sDump\ssent\ssuccessfully\sto\sremote\shost\!/ nocase ascii wide
                        $string4_RustiveDump_offensive_tool_keyword = /\\rustive\.dmp/ nocase ascii wide
                        $string5_RustiveDump_offensive_tool_keyword = /\\RustiveDump\.bin/ nocase ascii wide
                        $string6_RustiveDump_offensive_tool_keyword = /\\RustiveDump\.exe/ nocase ascii wide
                        $string7_RustiveDump_offensive_tool_keyword = "safedv/RustiveDump" nocase ascii wide

    condition:
        any of them
}