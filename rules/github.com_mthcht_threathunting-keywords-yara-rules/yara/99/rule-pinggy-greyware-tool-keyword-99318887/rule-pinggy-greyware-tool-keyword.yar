rule rule_pinggy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pinggy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pinggy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_pinggy_greyware_tool_keyword = /\sa\.pinggy\.io/ nocase ascii wide
                        $string2_pinggy_greyware_tool_keyword = /\.a\.pinggy\.online/ nocase ascii wide
                        $string3_pinggy_greyware_tool_keyword = /\.free\.pinggy\.online/ nocase ascii wide
                        $string4_pinggy_greyware_tool_keyword = /\/a\.pinggy\.io/ nocase ascii wide
                        $string5_pinggy_greyware_tool_keyword = /\@a\.pinggy\.io/ nocase ascii wide

    condition:
        any of them
}