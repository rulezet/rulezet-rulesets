rule rule_ssh_auditor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ssh-auditor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ssh-auditor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ssh_auditor_offensive_tool_keyword = "ssh-auditor" nocase ascii wide

    condition:
        any of them
}