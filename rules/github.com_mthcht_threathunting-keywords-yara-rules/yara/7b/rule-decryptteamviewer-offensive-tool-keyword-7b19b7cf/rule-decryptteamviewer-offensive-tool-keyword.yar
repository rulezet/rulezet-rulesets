rule rule_DecryptTeamViewer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DecryptTeamViewer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DecryptTeamViewer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DecryptTeamViewer_offensive_tool_keyword = /\/DecryptTeamViewer\.exe/ nocase ascii wide
                        $string2_DecryptTeamViewer_offensive_tool_keyword = /\/DecryptTeamViewer\.git/ nocase ascii wide
                        $string3_DecryptTeamViewer_offensive_tool_keyword = /\\DecryptTeamViewer\.exe/ nocase ascii wide
                        $string4_DecryptTeamViewer_offensive_tool_keyword = /\\DecryptTeamViewer\.sln/ nocase ascii wide
                        $string5_DecryptTeamViewer_offensive_tool_keyword = /\\DecryptTeamViewer\-master/ nocase ascii wide
                        $string6_DecryptTeamViewer_offensive_tool_keyword = "4aa99dcaf5030b1c4c7c57edd0fea22ab6db79caff79a547cc07572077631646" nocase ascii wide
                        $string7_DecryptTeamViewer_offensive_tool_keyword = "7ec9b36feeace5d4903be2adb2e1454af948a393c311b5513bfad0e9995b87e7" nocase ascii wide
                        $string8_DecryptTeamViewer_offensive_tool_keyword = "D6AAED62-BBFC-4F2A-A2A4-35EC5B2A4E07" nocase ascii wide
                        $string9_DecryptTeamViewer_offensive_tool_keyword = "DecryptTeamViewer: Pillaging registry for TeamViewer information" nocase ascii wide
                        $string10_DecryptTeamViewer_offensive_tool_keyword = /DecryptTeamViewer\-master\.zip/ nocase ascii wide
                        $string11_DecryptTeamViewer_offensive_tool_keyword = "V1V1/DecryptTeamViewer" nocase ascii wide

    condition:
        any of them
}