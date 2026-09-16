rule rule_gofile_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gofile.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gofile.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_gofile_io_greyware_tool_keyword = /\.gofile\.io\/uploadFile/ nocase ascii wide
                        $string2_gofile_io_greyware_tool_keyword = /api\.gofile\.io\/getServer/ nocase ascii wide

    condition:
        any of them
}