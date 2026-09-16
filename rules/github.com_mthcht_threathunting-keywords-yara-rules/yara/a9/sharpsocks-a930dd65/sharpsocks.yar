rule SharpSocks
{
    meta:
        description = "Detection patterns for the tool 'SharpSocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --beacon=" nocase ascii wide
                        $string2 = " --payloadcookie " nocase ascii wide
                        $string3 = "/SharpSocks" nocase ascii wide
                        $string4 = "--payload-cookie" nocase ascii wide
                        $string5 = "ProcessCommandChannelImplantMessage" nocase ascii wide
                        $string6 = "ProcessEncryptedC2Request" nocase ascii wide
                        $string7 = /SharpSocks\.exe/ nocase ascii wide
                        $string8 = /SharpSocks\.pfx/ nocase ascii wide
                        $string9 = /SharpSocks\.resx/ nocase ascii wide
                        $string10 = /SharpSocks\.sln/ nocase ascii wide
                        $string11 = "SharpSocksCommon" nocase ascii wide
                        $string12 = "SharpSocksConfig" nocase ascii wide
                        $string13 = "SharpSocksImplant" nocase ascii wide
                        $string14 = "SharpSocksServer" nocase ascii wide

    condition:
        any of them
}