rule rule_EyeWitness_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EyeWitness' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EyeWitness"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EyeWitness_offensive_tool_keyword = /Witness\.py/

    condition:
        any of them
}