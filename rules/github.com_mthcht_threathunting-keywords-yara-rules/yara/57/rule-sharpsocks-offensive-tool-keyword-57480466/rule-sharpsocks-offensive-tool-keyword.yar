rule rule_SharpSocks_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSocks_offensive_tool_keyword = " --beacon=" nocase ascii wide
                        $string2_SharpSocks_offensive_tool_keyword = " --payloadcookie " nocase ascii wide
                        $string3_SharpSocks_offensive_tool_keyword = "/SharpSocks" nocase ascii wide
                        $string4_SharpSocks_offensive_tool_keyword = "--payload-cookie" nocase ascii wide
                        $string5_SharpSocks_offensive_tool_keyword = "ProcessCommandChannelImplantMessage" nocase ascii wide
                        $string6_SharpSocks_offensive_tool_keyword = "ProcessEncryptedC2Request" nocase ascii wide
                        $string7_SharpSocks_offensive_tool_keyword = /SharpSocks\.exe/ nocase ascii wide
                        $string8_SharpSocks_offensive_tool_keyword = /SharpSocks\.pfx/ nocase ascii wide
                        $string9_SharpSocks_offensive_tool_keyword = /SharpSocks\.resx/ nocase ascii wide
                        $string10_SharpSocks_offensive_tool_keyword = /SharpSocks\.sln/ nocase ascii wide
                        $string11_SharpSocks_offensive_tool_keyword = "SharpSocksCommon" nocase ascii wide
                        $string12_SharpSocks_offensive_tool_keyword = "SharpSocksConfig" nocase ascii wide
                        $string13_SharpSocks_offensive_tool_keyword = "SharpSocksImplant" nocase ascii wide
                        $string14_SharpSocks_offensive_tool_keyword = "SharpSocksServer" nocase ascii wide

    condition:
        any of them
}