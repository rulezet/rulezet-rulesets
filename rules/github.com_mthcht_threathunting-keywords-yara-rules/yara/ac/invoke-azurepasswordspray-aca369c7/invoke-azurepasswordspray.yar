rule Invoke_AzurePasswordSpray
{
    meta:
        description = "Detection patterns for the tool 'Invoke-AzurePasswordSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-AzurePasswordSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Invoke-AzurePasswordSpray" nocase ascii wide

    condition:
        any of them
}