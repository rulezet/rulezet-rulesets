rule rule_BadWindowsService_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BadWindowsService' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadWindowsService"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BadWindowsService_offensive_tool_keyword = /\sBadWindowsService\.exe/ nocase ascii wide
                        $string2_BadWindowsService_offensive_tool_keyword = /\/BadWindowsService\.exe/ nocase ascii wide
                        $string3_BadWindowsService_offensive_tool_keyword = /\/BadWindowsService\.git/ nocase ascii wide
                        $string4_BadWindowsService_offensive_tool_keyword = /\\BadWindowsService\.cs/ nocase ascii wide
                        $string5_BadWindowsService_offensive_tool_keyword = /\\BadWindowsService\.exe/ nocase ascii wide
                        $string6_BadWindowsService_offensive_tool_keyword = /\\BadWindowsService\.sln/ nocase ascii wide
                        $string7_BadWindowsService_offensive_tool_keyword = /\\CurrentControlSet\\Services\\BadWindowsService/ nocase ascii wide
                        $string8_BadWindowsService_offensive_tool_keyword = /\\Program\sFiles\\Bad\sWindows\sService/ nocase ascii wide
                        $string9_BadWindowsService_offensive_tool_keyword = "1a88b6412bb1e6349948bc6abdc0eebb5df61cc8c0a7ec9709310a77dbc7bccb" nocase ascii wide
                        $string10_BadWindowsService_offensive_tool_keyword = "320ed251abc046f440dc0e76d00864d6cf5f65dee61988898d86c18e5513a8c9" nocase ascii wide
                        $string11_BadWindowsService_offensive_tool_keyword = "347e20ccd42d4346d9a1cb3255d77b493d3b1b52be12f72ccaa9085d6b5dd30f" nocase ascii wide
                        $string12_BadWindowsService_offensive_tool_keyword = "43A031B0-E040-4D5E-B477-02651F5E3D62" nocase ascii wide
                        $string13_BadWindowsService_offensive_tool_keyword = "4628fdac0a217dd268e3f962a7665348eb9cf64bda81313cbfb1617008a9dc2e" nocase ascii wide
                        $string14_BadWindowsService_offensive_tool_keyword = "6d820b495719031338017f6138fae3546f549e9e816274554f6c21a77149b778" nocase ascii wide
                        $string15_BadWindowsService_offensive_tool_keyword = "9a717740140d1848e3b2641af0a517cea689409951cb1262737b06ec398180e3" nocase ascii wide
                        $string16_BadWindowsService_offensive_tool_keyword = "acd65a0c933308d9a867fb3701e39787a386708fbaabd907d41b3decdb481ca2" nocase ascii wide
                        $string17_BadWindowsService_offensive_tool_keyword = "B474B962-A46B-4D35-86F3-E8BA120C88C0" nocase ascii wide
                        $string18_BadWindowsService_offensive_tool_keyword = /BadWindowsService_v1\.0\.7z/ nocase ascii wide
                        $string19_BadWindowsService_offensive_tool_keyword = /BadWindowsService_v1\.0\.zip/ nocase ascii wide
                        $string20_BadWindowsService_offensive_tool_keyword = "cc8bb64ef855405aeb66e480e8e7a2a65f61d495718fed2825083916cedd5e4c" nocase ascii wide
                        $string21_BadWindowsService_offensive_tool_keyword = "da8bf03ff487a649c28018f5e4d7bdac0e1ff1ed7ed67d6fa1b901c4dbc36a30" nocase ascii wide
                        $string22_BadWindowsService_offensive_tool_keyword = "eladshamir/BadWindowsService" nocase ascii wide
                        $string23_BadWindowsService_offensive_tool_keyword = /ServiceName.{0,1000}BadWindowsService/ nocase ascii wide
                        $string24_BadWindowsService_offensive_tool_keyword = "ZeroPointSecurity/BadWindowsService" nocase ascii wide

    condition:
        any of them
}