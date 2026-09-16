rule rule_Rock_ON_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Rock-ON' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rock-ON"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Rock_ON_offensive_tool_keyword = "SilverPoision/Rock-ON" nocase ascii wide

    condition:
        any of them
}