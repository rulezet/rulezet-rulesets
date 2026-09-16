rule rule_ZeroHVCI_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ZeroHVCI' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ZeroHVCI"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ZeroHVCI_offensive_tool_keyword = /\/ZeroHVCI\.exe/ nocase ascii wide
                        $string2_ZeroHVCI_offensive_tool_keyword = /\/ZeroHVCI\.git/ nocase ascii wide
                        $string3_ZeroHVCI_offensive_tool_keyword = /\\ZeroHVCI\.cpp/ nocase ascii wide
                        $string4_ZeroHVCI_offensive_tool_keyword = /\\ZeroHVCI\.exe/ nocase ascii wide
                        $string5_ZeroHVCI_offensive_tool_keyword = /\\ZeroHVCI\.sln/ nocase ascii wide
                        $string6_ZeroHVCI_offensive_tool_keyword = /\\ZeroHVCI\-master/ nocase ascii wide
                        $string7_ZeroHVCI_offensive_tool_keyword = "0269fd0001afa23edd1206484dccce04b49e0ec0daa65234126a6f3c42f35a46" nocase ascii wide
                        $string8_ZeroHVCI_offensive_tool_keyword = "95529189-2fb6-49e4-ab2d-3c925ada4414" nocase ascii wide
                        $string9_ZeroHVCI_offensive_tool_keyword = "c6206e0851a8c6ac7f9a9b6386a7ef7166cfbfc63d04f028cfdbe82ef523acbc" nocase ascii wide
                        $string10_ZeroHVCI_offensive_tool_keyword = /CSC_DEV_FCB_XXX_CONTROL_FILE.{0,1000}0x001401a3/ nocase ascii wide
                        $string11_ZeroHVCI_offensive_tool_keyword = "e49b696f9356d17861fb7ff0391a72841af546a18b1be587cf0d41dbdac982a4" nocase ascii wide
                        $string12_ZeroHVCI_offensive_tool_keyword = /https\:\/\/www\.youtube\.com\/watch\?v\=2eHsnZ4BeDI/ nocase ascii wide
                        $string13_ZeroHVCI_offensive_tool_keyword = "zer0condition/ZeroHVCI" nocase ascii wide

    condition:
        any of them
}