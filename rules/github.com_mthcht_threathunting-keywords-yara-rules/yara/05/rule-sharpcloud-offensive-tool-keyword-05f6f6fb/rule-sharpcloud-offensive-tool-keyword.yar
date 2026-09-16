rule rule_SharpCloud_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpCloud' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpCloud"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpCloud_offensive_tool_keyword = /\/SharpCloud\.git/ nocase ascii wide
                        $string2_SharpCloud_offensive_tool_keyword = "chrismaddalena/SharpCloud" nocase ascii wide
                        $string3_SharpCloud_offensive_tool_keyword = "execute_assembly SharpCloud" nocase ascii wide
                        $string4_SharpCloud_offensive_tool_keyword = /sharpcloud\.cna/ nocase ascii wide
                        $string5_SharpCloud_offensive_tool_keyword = /SharpCloud\.csproj/ nocase ascii wide
                        $string6_SharpCloud_offensive_tool_keyword = /SharpCloud\.exe/ nocase ascii wide
                        $string7_SharpCloud_offensive_tool_keyword = /SharpCloud\.sln/ nocase ascii wide
                        $string8_SharpCloud_offensive_tool_keyword = "SharpCloud-master" nocase ascii wide

    condition:
        any of them
}