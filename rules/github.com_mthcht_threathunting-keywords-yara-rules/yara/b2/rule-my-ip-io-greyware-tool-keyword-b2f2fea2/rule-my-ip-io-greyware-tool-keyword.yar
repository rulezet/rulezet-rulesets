rule rule_my_ip_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'my-ip.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "my-ip.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_my_ip_io_greyware_tool_keyword = /https\:\/\/api\.my\-ip\.io\/ip/ nocase ascii wide

    condition:
        any of them
}