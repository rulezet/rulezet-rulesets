rule rule_homeway_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'homeway.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "homeway.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_homeway_io_greyware_tool_keyword = /homeassistant\.local\:8123/ nocase ascii wide
                        $string2_homeway_io_greyware_tool_keyword = /https\:\/\/homeway\.io\/install\.sh/

    condition:
        any of them
}