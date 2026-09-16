rule WirelessKeyView
{
    meta:
        description = "Detection patterns for the tool 'WirelessKeyView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WirelessKeyView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " /GetKeys WirelessKeyView" nocase ascii wide
                        $string2 = ">Extracts wireless keys stored by Windows<" nocase ascii wide
                        $string3 = ">Wireless Key View<" nocase ascii wide
                        $string4 = "19bab15a34d5ad838ccf4d187eb40379c335fa56446d0f9621865b2767d4ac7d" nocase ascii wide
                        $string5 = "31ee7ee1add800239003806829b825cadc5b95797c11e33cf6b691571c1e2069" nocase ascii wide
                        $string6 = "5d17e9dd54752bf9071caeccace27123897fe33de26db8c6f3e544abd11f7cb2" nocase ascii wide
                        $string7 = /wirelesskeyview\.exe/ nocase ascii wide
                        $string8 = /wirelesskeyview\.exe/ nocase ascii wide
                        $string9 = /wirelesskeyview\.zip/ nocase ascii wide
                        $string10 = /wirelesskeyview\.zip/ nocase ascii wide
                        $string11 = /WirelessKeyView_x64\.exe/ nocase ascii wide
                        $string12 = /WirelessKeyView_x64\.exe/ nocase ascii wide
                        $string13 = /wirelesskeyview\-no\-command\-line\.zip/ nocase ascii wide
                        $string14 = /wirelesskeyview\-no\-command\-line\.zip/ nocase ascii wide
                        $string15 = /wirelesskeyview\-x64\.zip/ nocase ascii wide
                        $string16 = /wirelesskeyview\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}