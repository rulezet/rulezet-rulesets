rule rule__4shared_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '4shared.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "4shared.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1__4shared_com_greyware_tool_keyword = /4shared\.com\/.{0,1000}upload/ nocase ascii wide
                        $string2__4shared_com_greyware_tool_keyword = /https\:\/\/www\.4shared\.com\/get\// nocase ascii wide

    condition:
        any of them
}