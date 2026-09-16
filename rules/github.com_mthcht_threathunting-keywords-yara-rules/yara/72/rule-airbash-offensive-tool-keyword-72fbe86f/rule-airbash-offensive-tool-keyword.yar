rule rule_Airbash_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Airbash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Airbash"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Airbash_offensive_tool_keyword = "Airbash"

    condition:
        any of them
}