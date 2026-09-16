rule rule_filetransfer_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'filetransfer.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "filetransfer.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_filetransfer_io_greyware_tool_keyword = /filetransfer\.io\/upload\// nocase ascii wide

    condition:
        any of them
}