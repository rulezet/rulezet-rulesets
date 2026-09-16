rule rule_ShellPop_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShellPop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellPop"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShellPop_offensive_tool_keyword = "/ShellPop" nocase ascii wide

    condition:
        any of them
}