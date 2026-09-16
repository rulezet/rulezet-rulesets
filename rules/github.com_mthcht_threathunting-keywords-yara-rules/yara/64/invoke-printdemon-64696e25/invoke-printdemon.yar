rule Invoke_PrintDemon
{
    meta:
        description = "Detection patterns for the tool 'Invoke-PrintDemon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-PrintDemon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Invoke-PrintDemon" nocase ascii wide

    condition:
        any of them
}