rule rule_Koppeling_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Koppeling' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Koppeling"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Koppeling_offensive_tool_keyword = /\sNetClone\.exe/ nocase ascii wide
                        $string2_Koppeling_offensive_tool_keyword = /\sPyClone\.py/ nocase ascii wide
                        $string3_Koppeling_offensive_tool_keyword = /\sTheif\.dll/ nocase ascii wide
                        $string4_Koppeling_offensive_tool_keyword = /\/\.clone\.dll/ nocase ascii wide
                        $string5_Koppeling_offensive_tool_keyword = /\/Koppeling\.git/ nocase ascii wide
                        $string6_Koppeling_offensive_tool_keyword = /\/NetClone\.exe/ nocase ascii wide
                        $string7_Koppeling_offensive_tool_keyword = /\/PyClone\.py/ nocase ascii wide
                        $string8_Koppeling_offensive_tool_keyword = /\/Theif\.dll/ nocase ascii wide
                        $string9_Koppeling_offensive_tool_keyword = /\[\!\]\sDynamic\sSink\:\sBAD\\"\,\sL\\"Harness\\"/ nocase ascii wide
                        $string10_Koppeling_offensive_tool_keyword = /\\\.clone\.dll/ nocase ascii wide
                        $string11_Koppeling_offensive_tool_keyword = /\\Koppeling\.sln/ nocase ascii wide
                        $string12_Koppeling_offensive_tool_keyword = /\\NetClone\.exe/ nocase ascii wide
                        $string13_Koppeling_offensive_tool_keyword = /\\NetClone\\Program\.cs/ nocase ascii wide
                        $string14_Koppeling_offensive_tool_keyword = /\\PyClone\.py/ nocase ascii wide
                        $string15_Koppeling_offensive_tool_keyword = /\\Theif\.dll/ nocase ascii wide
                        $string16_Koppeling_offensive_tool_keyword = "1c9a4023737f0be81e06da3719ab68310dca400ca15cfb63012949215fb694eb" nocase ascii wide
                        $string17_Koppeling_offensive_tool_keyword = "2150D252-AA17-45C2-8981-A6DCF7055CA6" nocase ascii wide
                        $string18_Koppeling_offensive_tool_keyword = "491012428e225b620985e8fc2af087fe8b85ccd9c9cc0a37bd1385b62f317bbe" nocase ascii wide
                        $string19_Koppeling_offensive_tool_keyword = "62E3CCF4-07F3-496E-B77D-48D5AC0E6260" nocase ascii wide
                        $string20_Koppeling_offensive_tool_keyword = "8dd0633df72aacd10c634a263f6b1ade7195508e79993681e0800527ddfd86ef" nocase ascii wide
                        $string21_Koppeling_offensive_tool_keyword = "95BC2C38-1FBE-4AF1-967E-BC133250C4D4" nocase ascii wide
                        $string22_Koppeling_offensive_tool_keyword = "DB8A345D-E19C-4C2A-9FDF-16BF4DD03717" nocase ascii wide
                        $string23_Koppeling_offensive_tool_keyword = /Dyn\-NetClone\|x64/ nocase ascii wide
                        $string24_Koppeling_offensive_tool_keyword = /Dyn\-PyClone\|Win32/ nocase ascii wide
                        $string25_Koppeling_offensive_tool_keyword = "monoxgas/Koppeling" nocase ascii wide

    condition:
        any of them
}