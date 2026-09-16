rule rule_TakeMyRDP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TakeMyRDP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TakeMyRDP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TakeMyRDP_offensive_tool_keyword = "/TakeMyRDP" nocase ascii wide
                        $string2_TakeMyRDP_offensive_tool_keyword = /\\TakeMyRDP/ nocase ascii wide
                        $string3_TakeMyRDP_offensive_tool_keyword = "3C601672-7389-42B2-B5C9-059846E1DA88" nocase ascii wide
                        $string4_TakeMyRDP_offensive_tool_keyword = /TakeMyRDP.{0,1000}logfile\.txt/ nocase ascii wide
                        $string5_TakeMyRDP_offensive_tool_keyword = /TakeMyRDP\.cpp/ nocase ascii wide
                        $string6_TakeMyRDP_offensive_tool_keyword = /TakeMyRDP\.exe/ nocase ascii wide
                        $string7_TakeMyRDP_offensive_tool_keyword = /TakeMyRDP\.git/ nocase ascii wide
                        $string8_TakeMyRDP_offensive_tool_keyword = /TakeMyRDP\.h/ nocase ascii wide
                        $string9_TakeMyRDP_offensive_tool_keyword = /TakeMyRDP\.sln/ nocase ascii wide
                        $string10_TakeMyRDP_offensive_tool_keyword = /TakeMyRDP\.vcxproj/ nocase ascii wide
                        $string11_TakeMyRDP_offensive_tool_keyword = /TakeMyRDP2\.0/ nocase ascii wide
                        $string12_TakeMyRDP_offensive_tool_keyword = "TakeMyRDP-main" nocase ascii wide

    condition:
        any of them
}