rule kalitorify
{
    meta:
        description = "Detection patterns for the tool 'kalitorify' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kalitorify"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "kalitorify"

    condition:
        any of them
}