rule awesome_static_analysis
{
    meta:
        description = "Detection patterns for the tool 'awesome-static-analysis' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-static-analysis"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "awesome-static-analysis" nocase ascii wide

    condition:
        any of them
}