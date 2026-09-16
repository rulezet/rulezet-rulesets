rule HellsGate
{
    meta:
        description = "Detection patterns for the tool 'HellsGate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HellsGate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/HellsGate\.git/ nocase ascii wide
                        $string2 = "am0nsec/HellsGate" nocase ascii wide
                        $string3 = "DC6187CB-D5DF-4973-84A2-F92AAE90CDA9" nocase ascii wide
                        $string4 = /hellsgate\.asm/ nocase ascii wide
                        $string5 = /HellsGate\.exe/ nocase ascii wide
                        $string6 = /HellsGate\.sln/ nocase ascii wide
                        $string7 = /HellsGate\.vcxproj/ nocase ascii wide

    condition:
        any of them
}