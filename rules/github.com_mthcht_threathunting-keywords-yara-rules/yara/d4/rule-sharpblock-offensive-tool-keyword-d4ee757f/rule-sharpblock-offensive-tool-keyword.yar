rule rule_SharpBlock_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpBlock' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBlock"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpBlock_offensive_tool_keyword = /\s\-d\s.{0,1000}Active\sProtection\sDLL\sfor\sSylantStrike/ nocase ascii wide
                        $string2_SharpBlock_offensive_tool_keyword = " --disable-bypass-amsi" nocase ascii wide
                        $string3_SharpBlock_offensive_tool_keyword = " --disable-bypass-cmdline" nocase ascii wide
                        $string4_SharpBlock_offensive_tool_keyword = " --disable-bypass-etw" nocase ascii wide
                        $string5_SharpBlock_offensive_tool_keyword = "/SharpSploit/" nocase ascii wide
                        $string6_SharpBlock_offensive_tool_keyword = /\\\\\.\\pipe\\mimi/ nocase ascii wide
                        $string7_SharpBlock_offensive_tool_keyword = "execute-assembly SharpBlock" nocase ascii wide
                        $string8_SharpBlock_offensive_tool_keyword = "SharpBlock -" nocase ascii wide
                        $string9_SharpBlock_offensive_tool_keyword = /SharpBlock\.csproj/ nocase ascii wide
                        $string10_SharpBlock_offensive_tool_keyword = /SharpBlock\.exe/ nocase ascii wide
                        $string11_SharpBlock_offensive_tool_keyword = /SharpBlock\.sln/ nocase ascii wide

    condition:
        any of them
}