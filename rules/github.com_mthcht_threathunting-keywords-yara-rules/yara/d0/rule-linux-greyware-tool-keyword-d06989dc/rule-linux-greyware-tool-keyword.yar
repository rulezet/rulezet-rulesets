rule rule_linux_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'linux' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_linux_greyware_tool_keyword = /\:\(\)\{\:I\:\s\&I/

    condition:
        any of them
}