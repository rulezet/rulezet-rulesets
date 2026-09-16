rule pwn_jenkins
{
    meta:
        description = "Detection patterns for the tool 'pwn_jenkins' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwn_jenkins"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "pwn_jenkins" nocase ascii wide

    condition:
        any of them
}