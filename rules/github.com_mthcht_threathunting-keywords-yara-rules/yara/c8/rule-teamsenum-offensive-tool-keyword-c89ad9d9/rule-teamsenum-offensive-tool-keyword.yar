rule rule_TeamsEnum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TeamsEnum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TeamsEnum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TeamsEnum_offensive_tool_keyword = /\steamsenum\.py/ nocase ascii wide
                        $string2_TeamsEnum_offensive_tool_keyword = /\/TeamsEnum\.git/ nocase ascii wide
                        $string3_TeamsEnum_offensive_tool_keyword = /\/teamsenum\.py/ nocase ascii wide
                        $string4_TeamsEnum_offensive_tool_keyword = /\\teamsenum\.py/ nocase ascii wide
                        $string5_TeamsEnum_offensive_tool_keyword = "1228965bfca9be58b2370874d794ce293238ef8a7faa1f6c744374300aa8a79d" nocase ascii wide
                        $string6_TeamsEnum_offensive_tool_keyword = "5df59d3aeb2b438458b5dfe2a8f0bbc15da03a6c222d9cf57aff6df5f682ee31" nocase ascii wide
                        $string7_TeamsEnum_offensive_tool_keyword = /import\steamsenum\.auth/ nocase ascii wide
                        $string8_TeamsEnum_offensive_tool_keyword = "sse-secure-systems/TeamsEnum" nocase ascii wide

    condition:
        any of them
}