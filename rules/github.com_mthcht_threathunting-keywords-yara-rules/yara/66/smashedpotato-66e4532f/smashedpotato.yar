rule SmashedPotato
{
    meta:
        description = "Detection patterns for the tool 'SmashedPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SmashedPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /SmashedPotato\.cs/ nocase ascii wide
                        $string2 = /SmashedPotato\.exe/ nocase ascii wide

    condition:
        any of them
}