rule rule_InsecurePowerShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'InsecurePowerShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "InsecurePowerShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_InsecurePowerShell_offensive_tool_keyword = "InsecurePowerShell" nocase ascii wide

    condition:
        any of them
}