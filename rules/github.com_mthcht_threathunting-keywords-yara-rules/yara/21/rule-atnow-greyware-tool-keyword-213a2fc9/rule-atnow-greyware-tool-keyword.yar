rule rule_atnow_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'atnow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "atnow"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_atnow_greyware_tool_keyword = /\/atnow\.exe/ nocase ascii wide
                        $string2_atnow_greyware_tool_keyword = /\/atnow\.zip/ nocase ascii wide
                        $string3_atnow_greyware_tool_keyword = /\\AtNow\s\\\\/ nocase ascii wide
                        $string4_atnow_greyware_tool_keyword = /\\atnow\.exe/ nocase ascii wide
                        $string5_atnow_greyware_tool_keyword = /\\atnow\.zip/ nocase ascii wide
                        $string6_atnow_greyware_tool_keyword = ">Near-Future Command Scheduler<" nocase ascii wide
                        $string7_atnow_greyware_tool_keyword = "aa142160446a919eaba99ce15992f6e11b1fdaa7a9f569979a29068120f774cf" nocase ascii wide
                        $string8_atnow_greyware_tool_keyword = /ProductName.{0,1000}\>AtNow\</ nocase ascii wide

    condition:
        any of them
}