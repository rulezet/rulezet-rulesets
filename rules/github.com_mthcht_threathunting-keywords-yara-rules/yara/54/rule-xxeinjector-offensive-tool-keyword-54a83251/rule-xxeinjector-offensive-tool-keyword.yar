rule rule_XXEinjector_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'XXEinjector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "XXEinjector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_XXEinjector_offensive_tool_keyword = "XXEinjector" nocase ascii wide

    condition:
        any of them
}