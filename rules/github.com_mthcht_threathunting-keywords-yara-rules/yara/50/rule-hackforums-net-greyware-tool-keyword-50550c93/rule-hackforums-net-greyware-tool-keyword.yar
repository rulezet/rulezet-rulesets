rule rule_hackforums_net_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hackforums.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hackforums.net"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_hackforums_net_greyware_tool_keyword = /hackforums\.net\// nocase ascii wide

    condition:
        any of them
}