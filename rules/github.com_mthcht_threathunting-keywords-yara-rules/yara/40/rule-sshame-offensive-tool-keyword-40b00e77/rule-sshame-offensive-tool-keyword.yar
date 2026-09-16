rule rule_sshame_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshame' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshame"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sshame_offensive_tool_keyword = "/sshame"

    condition:
        any of them
}