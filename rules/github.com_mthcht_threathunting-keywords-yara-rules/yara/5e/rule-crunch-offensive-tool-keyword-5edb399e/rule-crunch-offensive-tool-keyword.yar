rule rule_crunch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'crunch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crunch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_crunch_offensive_tool_keyword = "/crunch-wordlist/" nocase ascii wide
                        $string2_crunch_offensive_tool_keyword = "apt install crunch" nocase ascii wide
                        $string3_crunch_offensive_tool_keyword = /crunch\s.{0,1000}\s\-o\s.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}