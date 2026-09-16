rule rule_MSBuildShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MSBuildShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSBuildShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MSBuildShell_offensive_tool_keyword = "MSBuildShell" nocase ascii wide

    condition:
        any of them
}