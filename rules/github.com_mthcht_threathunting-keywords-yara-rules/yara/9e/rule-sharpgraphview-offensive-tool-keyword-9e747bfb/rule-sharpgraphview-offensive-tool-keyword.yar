rule rule_SharpGraphView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpGraphView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGraphView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpGraphView_offensive_tool_keyword = " Invoke-CertToAccessToken -tenant " nocase ascii wide
                        $string2_SharpGraphView_offensive_tool_keyword = /\/SharpGraphView\.git/ nocase ascii wide
                        $string3_SharpGraphView_offensive_tool_keyword = /\\SharpGraphView\.sln/ nocase ascii wide
                        $string4_SharpGraphView_offensive_tool_keyword = /\\sharpgraphview\\/ nocase ascii wide
                        $string5_SharpGraphView_offensive_tool_keyword = ">SharpGraphView<" nocase ascii wide
                        $string6_SharpGraphView_offensive_tool_keyword = "2beff60039dfd82bd092bae6e69a92ed04cdcf7cfe597868bb161dbc15c3de73" nocase ascii wide
                        $string7_SharpGraphView_offensive_tool_keyword = "3922246663d030813506516c147f8281d8c81f1cdc1153238643f580b52093d7" nocase ascii wide
                        $string8_SharpGraphView_offensive_tool_keyword = "64d0026295c3c887bbcb256967aae006f4df254a2bc9418f9a1dc30fd6115ee1" nocase ascii wide
                        $string9_SharpGraphView_offensive_tool_keyword = "825E2088-EC7C-4AB0-852A-4F1FEF178E37" nocase ascii wide
                        $string10_SharpGraphView_offensive_tool_keyword = "mlcsec/SharpGraphView" nocase ascii wide
                        $string11_SharpGraphView_offensive_tool_keyword = /SharpGraph\.exe\sGet\-UserChatMessages\s\-id\s/ nocase ascii wide
                        $string12_SharpGraphView_offensive_tool_keyword = /SharpGraph\.exe\sList\-ChatMessages\s/ nocase ascii wide
                        $string13_SharpGraphView_offensive_tool_keyword = /SharpGraphView\.exe/ nocase ascii wide

    condition:
        any of them
}