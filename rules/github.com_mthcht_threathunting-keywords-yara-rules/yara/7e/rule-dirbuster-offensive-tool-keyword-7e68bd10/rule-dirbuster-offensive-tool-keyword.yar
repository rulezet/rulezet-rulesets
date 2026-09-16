rule rule_dirbuster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dirbuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirbuster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dirbuster_offensive_tool_keyword = "/burp-Dirbuster"

    condition:
        any of them
}