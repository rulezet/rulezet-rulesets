rule PassHunt
{
    meta:
        description = "Detection patterns for the tool 'PassHunt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassHunt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /Dionach.{0,1000}PassHunt/ nocase ascii wide
                        $string2 = /passhunt\.exe/ nocase ascii wide
                        $string3 = /passhunt\.py/ nocase ascii wide

    condition:
        any of them
}