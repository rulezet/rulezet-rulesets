rule rule_debugdfs_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'debugdfs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "debugdfs"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_debugdfs_greyware_tool_keyword = "debugfs /dev/"

    condition:
        any of them
}