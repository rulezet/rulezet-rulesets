rule rule_PowerStager_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerStager' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerStager"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PowerStager_offensive_tool_keyword = "powerstager" nocase ascii wide

    condition:
        any of them
}