rule rule_WebDeveloperSecurityChecklist_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WebDeveloperSecurityChecklist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WebDeveloperSecurityChecklist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WebDeveloperSecurityChecklist_offensive_tool_keyword = "WebDeveloperSecurityChecklist" nocase ascii wide

    condition:
        any of them
}