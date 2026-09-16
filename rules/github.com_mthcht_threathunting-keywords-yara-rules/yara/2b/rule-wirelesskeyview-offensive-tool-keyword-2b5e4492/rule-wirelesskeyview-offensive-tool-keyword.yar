rule rule_WirelessKeyView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WirelessKeyView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WirelessKeyView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WirelessKeyView_offensive_tool_keyword = " /GetKeys WirelessKeyView" nocase ascii wide
                        $string2_WirelessKeyView_offensive_tool_keyword = ">Extracts wireless keys stored by Windows<" nocase ascii wide
                        $string3_WirelessKeyView_offensive_tool_keyword = ">Wireless Key View<" nocase ascii wide
                        $string4_WirelessKeyView_offensive_tool_keyword = "19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d" nocase ascii wide
                        $string5_WirelessKeyView_offensive_tool_keyword = "31ee7ee1add800239003806829b825cadc5b95797c11e33cf6b691571c1e2069" nocase ascii wide
                        $string6_WirelessKeyView_offensive_tool_keyword = "5d17e9dd54752bf9071caeccace27123897fe33de26db8c6f3e544abd11f7cb2" nocase ascii wide
                        $string7_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\.exe/ nocase ascii wide
                        $string8_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\.exe/ nocase ascii wide
                        $string9_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\.zip/ nocase ascii wide
                        $string10_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\.zip/ nocase ascii wide
                        $string11_WirelessKeyView_offensive_tool_keyword = /WirelessKeyView_x64\.exe/ nocase ascii wide
                        $string12_WirelessKeyView_offensive_tool_keyword = /WirelessKeyView_x64\.exe/ nocase ascii wide
                        $string13_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\-no\-command\-line\.zip/ nocase ascii wide
                        $string14_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\-no\-command\-line\.zip/ nocase ascii wide
                        $string15_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\-x64\.zip/ nocase ascii wide
                        $string16_WirelessKeyView_offensive_tool_keyword = /wirelesskeyview\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}