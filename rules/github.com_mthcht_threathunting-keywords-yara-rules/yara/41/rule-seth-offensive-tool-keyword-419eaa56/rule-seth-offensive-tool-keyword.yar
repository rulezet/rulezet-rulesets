rule rule_Seth_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Seth' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Seth"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Seth_offensive_tool_keyword = /\.\/seth\.sh\s.{0,1000}\s/
                        $string2_Seth_offensive_tool_keyword = /\.py\s.{0,1000}\s\-\-fake\-server/ nocase ascii wide
                        $string3_Seth_offensive_tool_keyword = "arpspoof -i " nocase ascii wide
                        $string4_Seth_offensive_tool_keyword = "Server enforces NLA; switching to 'fake server' mode" nocase ascii wide
                        $string5_Seth_offensive_tool_keyword = "Seth by SySS GmbH" nocase ascii wide
                        $string6_Seth_offensive_tool_keyword = /seth\.py\s.{0,1000}\s\-j\sINJECT/ nocase ascii wide
                        $string7_Seth_offensive_tool_keyword = /Seth\-master\.zip/ nocase ascii wide
                        $string8_Seth_offensive_tool_keyword = "SySS-Research/Seth" nocase ascii wide

    condition:
        any of them
}