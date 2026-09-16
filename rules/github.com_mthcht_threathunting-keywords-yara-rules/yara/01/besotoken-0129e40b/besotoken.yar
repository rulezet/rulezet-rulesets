rule BesoToken
{
    meta:
        description = "Detection patterns for the tool 'BesoToken' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BesoToken"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\sexec\s.{0,1000}\scmd\sinteractive/ nocase ascii wide
                        $string2 = /\/BesoToken\.cpp/ nocase ascii wide
                        $string3 = /\/BesoToken\.exe/ nocase ascii wide
                        $string4 = /\/BesoToken\.git/ nocase ascii wide
                        $string5 = /\[\+\]\sOpened\sProcess\sToken\sSucessufully\!/ nocase ascii wide
                        $string6 = /\\BesoToken\.cpp/ nocase ascii wide
                        $string7 = /\\BesoToken\.exe/ nocase ascii wide
                        $string8 = /\\BesoToken\.vcxproj/ nocase ascii wide
                        $string9 = "55A48A19-1A5C-4E0D-A46A-5DB04C1D8B03" nocase ascii wide
                        $string10 = /BesoToken\.exe\slist/ nocase ascii wide
                        $string11 = "BesoToken-master" nocase ascii wide
                        $string12 = "OmriBaso/BesoToken" nocase ascii wide

    condition:
        any of them
}