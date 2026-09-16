rule RustiveDump
{
    meta:
        description = "Detection patterns for the tool 'RustiveDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustiveDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/RustiveDump\.exe/ nocase ascii wide
                        $string2 = /\/RustiveDump\.git/ nocase ascii wide
                        $string3 = /\[\+\]\sDump\ssent\ssuccessfully\sto\sremote\shost\!/ nocase ascii wide
                        $string4 = /\\rustive\.dmp/ nocase ascii wide
                        $string5 = /\\RustiveDump\.bin/ nocase ascii wide
                        $string6 = /\\RustiveDump\.exe/ nocase ascii wide
                        $string7 = "safedv/RustiveDump" nocase ascii wide

    condition:
        any of them
}