rule linux
{
    meta:
        description = "Detection patterns for the tool 'linux' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\:\(\)\{\:I\:\s\&I/

    condition:
        any of them
}