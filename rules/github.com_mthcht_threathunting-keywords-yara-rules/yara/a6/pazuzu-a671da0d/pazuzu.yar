rule Pazuzu
{
    meta:
        description = "Detection patterns for the tool 'Pazuzu' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pazuzu"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /BorjaMerino.{0,1000}Pazuzu/ nocase ascii wide

    condition:
        any of them
}