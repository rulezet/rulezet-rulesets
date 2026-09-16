rule rule_put_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'put.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "put.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_put_io_greyware_tool_keyword = /https\:\/\/put\.io\/\?login/ nocase ascii wide
                        $string2_put_io_greyware_tool_keyword = /https\:\/\/put\.io\/default\/magnet\?url\=/ nocase ascii wide
                        $string3_put_io_greyware_tool_keyword = /https\:\/\/put\.io\/transfers/ nocase ascii wide
                        $string4_put_io_greyware_tool_keyword = /https\:\/\/put\.io\/v2\/oauth2\/register/ nocase ascii wide

    condition:
        any of them
}