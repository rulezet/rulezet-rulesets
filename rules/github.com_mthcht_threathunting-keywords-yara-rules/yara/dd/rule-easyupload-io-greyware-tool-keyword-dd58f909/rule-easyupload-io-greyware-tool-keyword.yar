rule rule_easyupload_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'easyupload.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "easyupload.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_easyupload_io_greyware_tool_keyword = /https\:\/\/easyupload\.io\// nocase ascii wide
                        $string2_easyupload_io_greyware_tool_keyword = /https\:\/\/easyupload\.io\/action\.php/ nocase ascii wide
                        $string3_easyupload_io_greyware_tool_keyword = /https\:\/\/easyupload\.io\/cdn\-cgi\/rum/ nocase ascii wide
                        $string4_easyupload_io_greyware_tool_keyword = /upload4\.easyupload\.io/ nocase ascii wide

    condition:
        any of them
}