rule rule_RedTeam_toolkit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RedTeam_toolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedTeam_toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RedTeam_toolkit_offensive_tool_keyword = "/Jira-Lens/" nocase ascii wide
                        $string2_RedTeam_toolkit_offensive_tool_keyword = "/RedTeam_toolkit" nocase ascii wide
                        $string3_RedTeam_toolkit_offensive_tool_keyword = /cvescanner\.py/ nocase ascii wide
                        $string4_RedTeam_toolkit_offensive_tool_keyword = /dirscanner\.py/ nocase ascii wide
                        $string5_RedTeam_toolkit_offensive_tool_keyword = /rdpbrute\.py/ nocase ascii wide

    condition:
        any of them
}