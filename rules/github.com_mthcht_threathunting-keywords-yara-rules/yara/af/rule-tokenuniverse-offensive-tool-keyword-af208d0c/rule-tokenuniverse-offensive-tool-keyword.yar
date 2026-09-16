rule rule_TokenUniverse_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TokenUniverse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenUniverse"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TokenUniverse_offensive_tool_keyword = /\sTokenUniverse\.zip/ nocase ascii wide
                        $string2_TokenUniverse_offensive_tool_keyword = /\/TokenUniverse\.git/ nocase ascii wide
                        $string3_TokenUniverse_offensive_tool_keyword = /\/TokenUniverse\.zip/ nocase ascii wide
                        $string4_TokenUniverse_offensive_tool_keyword = /\\TokenUniverse\.zip/ nocase ascii wide
                        $string5_TokenUniverse_offensive_tool_keyword = /\\TokenUniverse\\TokenUniverse\./ nocase ascii wide
                        $string6_TokenUniverse_offensive_tool_keyword = "diversenok/TokenUniverse" nocase ascii wide
                        $string7_TokenUniverse_offensive_tool_keyword = /TokenUniverse\.dproj/ nocase ascii wide
                        $string8_TokenUniverse_offensive_tool_keyword = /TokenUniverse\.exe/ nocase ascii wide
                        $string9_TokenUniverse_offensive_tool_keyword = /TokenUniverse\-master\.zip/ nocase ascii wide
                        $string10_TokenUniverse_offensive_tool_keyword = /TokenUniverse\-x64\.zip/ nocase ascii wide
                        $string11_TokenUniverse_offensive_tool_keyword = /TokenUniverse\-x86\.zip/ nocase ascii wide

    condition:
        any of them
}