rule rule_SharpClipboard_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpClipboard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpClipboard"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpClipboard_offensive_tool_keyword = /\/SharpClipboard\.git/ nocase ascii wide
                        $string2_SharpClipboard_offensive_tool_keyword = /\\SharpClipboard\.csproj/ nocase ascii wide
                        $string3_SharpClipboard_offensive_tool_keyword = /\\SharpClipboard\.sln/ nocase ascii wide
                        $string4_SharpClipboard_offensive_tool_keyword = /\\SharpClipboard\\/ nocase ascii wide
                        $string5_SharpClipboard_offensive_tool_keyword = ">SharpClipboard<" nocase ascii wide
                        $string6_SharpClipboard_offensive_tool_keyword = "0556d3a1e4719382613891895582f8a392ccacfab6814bc9deafa9c99c86e553" nocase ascii wide
                        $string7_SharpClipboard_offensive_tool_keyword = "1ff4136cc59aec4f76d776abce00a592679490763f669a44eeead8f88c4a3c07" nocase ascii wide
                        $string8_SharpClipboard_offensive_tool_keyword = "803c76c8edc3cb686137d642d75fcedd54b89461c719504f2e5f8a3235c3f7c3" nocase ascii wide
                        $string9_SharpClipboard_offensive_tool_keyword = "97484211-4726-4129-86AA-AE01D17690BE" nocase ascii wide
                        $string10_SharpClipboard_offensive_tool_keyword = "981d1e5d88087f716ebb0cf8b39ffe7d3e44c36bc1e34452c8eaf2eaa56c05f9" nocase ascii wide
                        $string11_SharpClipboard_offensive_tool_keyword = /SharpClipboard\.exe/ nocase ascii wide
                        $string12_SharpClipboard_offensive_tool_keyword = /SharpClipboard\-master\.zip/ nocase ascii wide
                        $string13_SharpClipboard_offensive_tool_keyword = "slyd0g/SharpClipboard" nocase ascii wide

    condition:
        any of them
}