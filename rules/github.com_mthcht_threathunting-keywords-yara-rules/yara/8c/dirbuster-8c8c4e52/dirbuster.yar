rule dirbuster
{
    meta:
        description = "Detection patterns for the tool 'dirbuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirbuster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/burp-Dirbuster"

    condition:
        any of them
}