rule rule_export_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'export' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "export"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_export_greyware_tool_keyword = "export HISTFILE=/dev/null"
                        $string2_export_greyware_tool_keyword = "export HISTFILESIZE=0"
                        $string3_export_greyware_tool_keyword = "export HISTSIZE=0"

    condition:
        any of them
}