rule Invoke_ProcessScan
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ProcessScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ProcessScan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Invoke-ProcessScan" nocase ascii wide

    condition:
        any of them
}