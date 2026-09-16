rule rule_btunnel_in_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'btunnel.in' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "btunnel.in"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_btunnel_in_greyware_tool_keyword = /https\:\/\/.{0,1000}\.btunnel\.co\.in/ nocase ascii wide

    condition:
        any of them
}