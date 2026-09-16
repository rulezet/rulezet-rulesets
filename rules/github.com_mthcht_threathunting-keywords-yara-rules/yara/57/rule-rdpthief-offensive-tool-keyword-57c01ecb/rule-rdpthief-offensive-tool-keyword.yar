rule rule_RdpThief_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RdpThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpThief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RdpThief_offensive_tool_keyword = "/RdpThief" nocase ascii wide
                        $string2_RdpThief_offensive_tool_keyword = /\/RdpThief\.git/ nocase ascii wide
                        $string3_RdpThief_offensive_tool_keyword = /\\RdpThief\./ nocase ascii wide
                        $string4_RdpThief_offensive_tool_keyword = /\\RdpThief_x64\./ nocase ascii wide
                        $string5_RdpThief_offensive_tool_keyword = "0x09AL/RdpThief" nocase ascii wide
                        $string6_RdpThief_offensive_tool_keyword = "71461ca71bcebb5fefa9394fe8e9a5a47c102195064d1f4cb5f24d330c9be97d" nocase ascii wide
                        $string7_RdpThief_offensive_tool_keyword = "ae320a69dd18e08c9cfb026f247978522ffde2acddeff93a5406c9b584dbc430" nocase ascii wide
                        $string8_RdpThief_offensive_tool_keyword = "ae320a69dd18e08c9cfb026f247978522ffde2acddeff93a5406c9b584dbc430" nocase ascii wide
                        $string9_RdpThief_offensive_tool_keyword = "BEBE6A01-0C03-4A7C-8FE9-9285F01C0B03" nocase ascii wide
                        $string10_RdpThief_offensive_tool_keyword = "BEBE6A01-0C03-4A7C-8FE9-9285F01C0B03" nocase ascii wide
                        $string11_RdpThief_offensive_tool_keyword = "cd7e4cd71cb803de24f7b8fc6c6946f96e9b9a95dd3c0888309b42446ba87b94" nocase ascii wide
                        $string12_RdpThief_offensive_tool_keyword = "d0fd70c59cf45c5c1eb9c73ba1ccfa433d715a3a57b1312a26a02c60210cbfb8" nocase ascii wide
                        $string13_RdpThief_offensive_tool_keyword = "d0fd70c59cf45c5c1eb9c73ba1ccfa433d715a3a57b1312a26a02c60210cbfb8" nocase ascii wide
                        $string14_RdpThief_offensive_tool_keyword = "Disabling RdpThief" nocase ascii wide
                        $string15_RdpThief_offensive_tool_keyword = "RdpThief enabled " nocase ascii wide
                        $string16_RdpThief_offensive_tool_keyword = /RdpThief\.dll/ nocase ascii wide
                        $string17_RdpThief_offensive_tool_keyword = /RdpThief\.exe/ nocase ascii wide
                        $string18_RdpThief_offensive_tool_keyword = /RdpThief_x64\.tmp/ nocase ascii wide

    condition:
        any of them
}