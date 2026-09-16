rule Jira_Lens
{
    meta:
        description = "Detection patterns for the tool 'Jira-Lens' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jira-Lens"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Jira\-Lens\.git/ nocase ascii wide
                        $string2 = "install Jira-Lens" nocase ascii wide
                        $string3 = "Invoke-ShareFinder" nocase ascii wide
                        $string4 = /Jira\-Lens\.py/ nocase ascii wide
                        $string5 = "MayankPandey01/Jira-Lens" nocase ascii wide

    condition:
        any of them
}