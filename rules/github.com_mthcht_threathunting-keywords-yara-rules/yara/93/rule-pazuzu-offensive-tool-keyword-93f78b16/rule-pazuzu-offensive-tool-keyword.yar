rule rule_Pazuzu_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Pazuzu' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pazuzu"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Pazuzu_offensive_tool_keyword = /BorjaMerino.{0,1000}Pazuzu/ nocase ascii wide

    condition:
        any of them
}