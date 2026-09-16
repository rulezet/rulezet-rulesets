rule RedTeam_toolkit
{
    meta:
        description = "Detection patterns for the tool 'RedTeam_toolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedTeam_toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/Jira-Lens/" nocase ascii wide
                        $string2 = "/RedTeam_toolkit" nocase ascii wide
                        $string3 = /cvescanner\.py/ nocase ascii wide
                        $string4 = /dirscanner\.py/ nocase ascii wide
                        $string5 = /rdpbrute\.py/ nocase ascii wide

    condition:
        any of them
}