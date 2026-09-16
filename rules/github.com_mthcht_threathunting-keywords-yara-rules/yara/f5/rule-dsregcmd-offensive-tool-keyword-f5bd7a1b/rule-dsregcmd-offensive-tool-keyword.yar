rule rule_dsregcmd_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dsregcmd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dsregcmd"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dsregcmd_offensive_tool_keyword = /dsregcmd\.exe\s\/status/ nocase ascii wide

    condition:
        any of them
}