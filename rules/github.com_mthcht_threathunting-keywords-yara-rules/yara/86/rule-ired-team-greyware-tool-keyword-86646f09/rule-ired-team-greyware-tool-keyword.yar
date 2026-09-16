rule rule_ired_team_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ired.team' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ired.team"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_ired_team_greyware_tool_keyword = /\/RedTeaming\-Tactics\-and\-Techniques\.git/ nocase ascii wide
                        $string2_ired_team_greyware_tool_keyword = /\\RedTeaming\-Tactics\-and\-Techniques\-master/ nocase ascii wide
                        $string3_ired_team_greyware_tool_keyword = "mantvydasb/RedTeaming-Tactics-and-Techniques" nocase ascii wide
                        $string4_ired_team_greyware_tool_keyword = /www\.ired\.team/ nocase ascii wide

    condition:
        any of them
}