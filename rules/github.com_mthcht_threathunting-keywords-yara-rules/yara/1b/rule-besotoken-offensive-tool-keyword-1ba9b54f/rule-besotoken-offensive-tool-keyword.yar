rule rule_BesoToken_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BesoToken' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BesoToken"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BesoToken_offensive_tool_keyword = /\.exe\sexec\s.{0,1000}\scmd\sinteractive/ nocase ascii wide
                        $string2_BesoToken_offensive_tool_keyword = /\/BesoToken\.cpp/ nocase ascii wide
                        $string3_BesoToken_offensive_tool_keyword = /\/BesoToken\.exe/ nocase ascii wide
                        $string4_BesoToken_offensive_tool_keyword = /\/BesoToken\.git/ nocase ascii wide
                        $string5_BesoToken_offensive_tool_keyword = /\[\+\]\sOpened\sProcess\sToken\sSucessufully\!/ nocase ascii wide
                        $string6_BesoToken_offensive_tool_keyword = /\\BesoToken\.cpp/ nocase ascii wide
                        $string7_BesoToken_offensive_tool_keyword = /\\BesoToken\.exe/ nocase ascii wide
                        $string8_BesoToken_offensive_tool_keyword = /\\BesoToken\.vcxproj/ nocase ascii wide
                        $string9_BesoToken_offensive_tool_keyword = "55A48A19-1A5C-4E0D-A46A-5DB04C1D8B03" nocase ascii wide
                        $string10_BesoToken_offensive_tool_keyword = /BesoToken\.exe\slist/ nocase ascii wide
                        $string11_BesoToken_offensive_tool_keyword = "BesoToken-master" nocase ascii wide
                        $string12_BesoToken_offensive_tool_keyword = "OmriBaso/BesoToken" nocase ascii wide

    condition:
        any of them
}