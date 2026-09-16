rule TakeMyRDP
{
    meta:
        description = "Detection patterns for the tool 'TakeMyRDP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TakeMyRDP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/TakeMyRDP" nocase ascii wide
                        $string2 = /\\TakeMyRDP/ nocase ascii wide
                        $string3 = "3C601672-7389-42B2-B5C9-059846E1DA88" nocase ascii wide
                        $string4 = /TakeMyRDP.{0,1000}logfile\.txt/ nocase ascii wide
                        $string5 = /TakeMyRDP\.cpp/ nocase ascii wide
                        $string6 = /TakeMyRDP\.exe/ nocase ascii wide
                        $string7 = /TakeMyRDP\.git/ nocase ascii wide
                        $string8 = /TakeMyRDP\.h/ nocase ascii wide
                        $string9 = /TakeMyRDP\.sln/ nocase ascii wide
                        $string10 = /TakeMyRDP\.vcxproj/ nocase ascii wide
                        $string11 = /TakeMyRDP2\.0/ nocase ascii wide
                        $string12 = "TakeMyRDP-main" nocase ascii wide

    condition:
        any of them
}