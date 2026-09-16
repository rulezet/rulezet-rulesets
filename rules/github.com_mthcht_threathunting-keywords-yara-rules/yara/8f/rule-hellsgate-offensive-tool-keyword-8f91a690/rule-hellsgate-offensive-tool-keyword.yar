rule rule_HellsGate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HellsGate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HellsGate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HellsGate_offensive_tool_keyword = /\/HellsGate\.git/ nocase ascii wide
                        $string2_HellsGate_offensive_tool_keyword = "am0nsec/HellsGate" nocase ascii wide
                        $string3_HellsGate_offensive_tool_keyword = "DC6187CB-D5DF-4973-84A2-F92AAE90CDA9" nocase ascii wide
                        $string4_HellsGate_offensive_tool_keyword = /hellsgate\.asm/ nocase ascii wide
                        $string5_HellsGate_offensive_tool_keyword = /HellsGate\.exe/ nocase ascii wide
                        $string6_HellsGate_offensive_tool_keyword = /HellsGate\.sln/ nocase ascii wide
                        $string7_HellsGate_offensive_tool_keyword = /HellsGate\.vcxproj/ nocase ascii wide

    condition:
        any of them
}