rule rule__12ft_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '12ft.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "12ft.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1__12ft_io_greyware_tool_keyword = /https\:\/\/12ft\.io\/api\/proxy\?q\=http/ nocase ascii wide
                        $string2__12ft_io_greyware_tool_keyword = /https\:\/\/12ft\.io\/proxy\?q\=/ nocase ascii wide

    condition:
        any of them
}