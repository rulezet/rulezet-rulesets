rule rule_ls_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ls' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ls"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ls_greyware_tool_keyword = /ls\s\\\\1.{0,1000}\..{0,1000}\..{0,1000}\..{0,1000}\\IPC\$\\/ nocase ascii wide

    condition:
        any of them
}