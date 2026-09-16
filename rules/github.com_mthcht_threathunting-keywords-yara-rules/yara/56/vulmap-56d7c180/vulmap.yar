rule Vulmap
{
    meta:
        description = "Detection patterns for the tool 'Vulmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Vulmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/vulmap\// nocase ascii wide
                        $string2 = /vulmon.{0,1000}Vulmap/

    condition:
        any of them
}