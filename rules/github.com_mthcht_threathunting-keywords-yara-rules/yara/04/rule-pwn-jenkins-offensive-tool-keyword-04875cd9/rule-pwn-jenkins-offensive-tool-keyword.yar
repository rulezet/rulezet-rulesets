rule rule_pwn_jenkins_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pwn_jenkins' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwn_jenkins"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pwn_jenkins_offensive_tool_keyword = "pwn_jenkins" nocase ascii wide

    condition:
        any of them
}