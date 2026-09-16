rule netsniff_ng
{
    meta:
        description = "Detection patterns for the tool 'netsniff-ng' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netsniff-ng"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "netsniff-ng"

    condition:
        any of them
}