rule AtlasC2
{
    meta:
        description = "Detection patterns for the tool 'AtlasC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AtlasC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /AtlasC2.{0,1000}APIModels/ nocase ascii wide
                        $string2 = /AtlasC2.{0,1000}Client/ nocase ascii wide
                        $string3 = /AtlasC2.{0,1000}implant/ nocase ascii wide
                        $string4 = /AtlasC2.{0,1000}TeamServer/ nocase ascii wide
                        $string5 = /AtlasC2\.exe/ nocase ascii wide
                        $string6 = /AtlasC2b\.exe/ nocase ascii wide
                        $string7 = /AtlasC2b\.sln/ nocase ascii wide
                        $string8 = /AtlasImplant\.yar/ nocase ascii wide
                        $string9 = "Gr1mmie/AtlasC2" nocase ascii wide

    condition:
        any of them
}