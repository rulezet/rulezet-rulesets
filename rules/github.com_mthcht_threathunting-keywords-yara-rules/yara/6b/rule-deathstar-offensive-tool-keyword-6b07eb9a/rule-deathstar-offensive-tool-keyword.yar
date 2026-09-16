rule rule_DeathStar_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DeathStar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DeathStar"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DeathStar_offensive_tool_keyword = /github.{0,1000}\/DeathStar/ nocase ascii wide

    condition:
        any of them
}