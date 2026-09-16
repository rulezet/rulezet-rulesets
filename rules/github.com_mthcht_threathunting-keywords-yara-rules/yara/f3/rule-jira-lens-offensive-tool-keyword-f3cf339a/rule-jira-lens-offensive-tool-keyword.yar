rule rule_Jira_Lens_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Jira-Lens' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jira-Lens"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Jira_Lens_offensive_tool_keyword = /\/Jira\-Lens\.git/ nocase ascii wide
                        $string2_Jira_Lens_offensive_tool_keyword = "install Jira-Lens" nocase ascii wide
                        $string3_Jira_Lens_offensive_tool_keyword = "Invoke-ShareFinder" nocase ascii wide
                        $string4_Jira_Lens_offensive_tool_keyword = /Jira\-Lens\.py/ nocase ascii wide
                        $string5_Jira_Lens_offensive_tool_keyword = "MayankPandey01/Jira-Lens" nocase ascii wide

    condition:
        any of them
}