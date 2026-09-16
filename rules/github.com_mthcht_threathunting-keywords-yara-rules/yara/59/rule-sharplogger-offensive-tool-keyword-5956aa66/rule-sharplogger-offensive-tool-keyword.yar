rule rule_SharpLogger_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpLogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpLogger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpLogger_offensive_tool_keyword = /\/SharpLogger\.exe/ nocase ascii wide
                        $string2_SharpLogger_offensive_tool_keyword = /\\SharpLogger\.exe/ nocase ascii wide
                        $string3_SharpLogger_offensive_tool_keyword = "36E00152-E073-4DA8-AA0C-375B6DD680C4" nocase ascii wide
                        $string4_SharpLogger_offensive_tool_keyword = "4dbd32931bc77778850c20282a9e3adebd4d23b7ef4b0635380b520c432b48d9" nocase ascii wide
                        $string5_SharpLogger_offensive_tool_keyword = "9d7bfb3aeba4145896ece197216c4269deee6cce93eed3ffafe442ed05aeb4c4" nocase ascii wide
                        $string6_SharpLogger_offensive_tool_keyword = "djhohnstein/SharpLogger" nocase ascii wide
                        $string7_SharpLogger_offensive_tool_keyword = /Keylogger\.csproj/ nocase ascii wide
                        $string8_SharpLogger_offensive_tool_keyword = /Keylogger\.exe/ nocase ascii wide
                        $string9_SharpLogger_offensive_tool_keyword = "namespace Keylogger" nocase ascii wide

    condition:
        any of them
}