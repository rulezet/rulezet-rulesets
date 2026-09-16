rule rule_serveo_net_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'serveo.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "serveo.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_serveo_net_greyware_tool_keyword = /http\:\/\/.{0,1000}\.serveo\.net/ nocase ascii wide
                        $string2_serveo_net_greyware_tool_keyword = /https\:\/\/.{0,1000}\.serveo\.net/ nocase ascii wide

    condition:
        any of them
}