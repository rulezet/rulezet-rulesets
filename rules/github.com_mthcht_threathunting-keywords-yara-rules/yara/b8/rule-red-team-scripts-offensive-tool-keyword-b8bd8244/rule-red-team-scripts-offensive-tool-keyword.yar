rule rule_red_team_scripts_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'red-team-scripts' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "red-team-scripts"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_red_team_scripts_offensive_tool_keyword = /enumerate\.cna/ nocase ascii wide
                        $string2_red_team_scripts_offensive_tool_keyword = /HostEnum\.ps1/ nocase ascii wide
                        $string3_red_team_scripts_offensive_tool_keyword = "Invoke-HostEnum" nocase ascii wide

    condition:
        any of them
}