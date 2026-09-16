rule rule_SharpGhostTask_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpGhostTask' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGhostTask"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpGhostTask_offensive_tool_keyword = /\.exe\s\-\-targettask\s.{0,1000}\s\-\-targetbinary\s\s/ nocase ascii wide
                        $string2_SharpGhostTask_offensive_tool_keyword = "/SharpGhostTask" nocase ascii wide
                        $string3_SharpGhostTask_offensive_tool_keyword = /\\SharpGhostTask/ nocase ascii wide
                        $string4_SharpGhostTask_offensive_tool_keyword = "1A8C9BD8-1800-46B0-8E22-7D3823C68366" nocase ascii wide
                        $string5_SharpGhostTask_offensive_tool_keyword = /SharpGhostTask\.csproj/ nocase ascii wide
                        $string6_SharpGhostTask_offensive_tool_keyword = /SharpGhostTask\.exe/ nocase ascii wide
                        $string7_SharpGhostTask_offensive_tool_keyword = /SharpGhostTask\.sln/ nocase ascii wide

    condition:
        any of them
}