rule Koppeling
{
    meta:
        description = "Detection patterns for the tool 'Koppeling' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Koppeling"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sNetClone\.exe/ nocase ascii wide
                        $string2 = /\sPyClone\.py/ nocase ascii wide
                        $string3 = /\sTheif\.dll/ nocase ascii wide
                        $string4 = /\/\.clone\.dll/ nocase ascii wide
                        $string5 = /\/Koppeling\.git/ nocase ascii wide
                        $string6 = /\/NetClone\.exe/ nocase ascii wide
                        $string7 = /\/PyClone\.py/ nocase ascii wide
                        $string8 = /\/Theif\.dll/ nocase ascii wide
                        $string9 = /\[\!\]\sDynamic\sSink\:\sBAD\\"\,\sL\\"Harness\\"/ nocase ascii wide
                        $string10 = /\\\.clone\.dll/ nocase ascii wide
                        $string11 = /\\Koppeling\.sln/ nocase ascii wide
                        $string12 = /\\NetClone\.exe/ nocase ascii wide
                        $string13 = /\\NetClone\\Program\.cs/ nocase ascii wide
                        $string14 = /\\PyClone\.py/ nocase ascii wide
                        $string15 = /\\Theif\.dll/ nocase ascii wide
                        $string16 = "1c9a4023737f0be81e06da3719ab68310dca400ca15cfb63012949215fb694eb" nocase ascii wide
                        $string17 = "2150D252-AA17-45C2-8981-A6DCF7055CA6" nocase ascii wide
                        $string18 = "491012428e225b620985e8fc2af087fe8b85ccd9c9cc0a37bd1385b62f317bbe" nocase ascii wide
                        $string19 = "62E3CCF4-07F3-496E-B77D-48D5AC0E6260" nocase ascii wide
                        $string20 = "8dd0633df72aacd10c634a263f6b1ade7195508e79993681e0800527ddfd86ef" nocase ascii wide
                        $string21 = "95BC2C38-1FBE-4AF1-967E-BC133250C4D4" nocase ascii wide
                        $string22 = "DB8A345D-E19C-4C2A-9FDF-16BF4DD03717" nocase ascii wide
                        $string23 = /Dyn\-NetClone\|x64/ nocase ascii wide
                        $string24 = /Dyn\-PyClone\|Win32/ nocase ascii wide
                        $string25 = "monoxgas/Koppeling" nocase ascii wide

    condition:
        any of them
}