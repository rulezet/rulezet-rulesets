rule rule_file_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'file.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "file.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_file_io_greyware_tool_keyword = /https\:\/\/file\.io\// nocase ascii wide
                        $string2_file_io_greyware_tool_keyword = /https\:\/\/file\.io\/\?title\=/ nocase ascii wide

    condition:
        any of them
}