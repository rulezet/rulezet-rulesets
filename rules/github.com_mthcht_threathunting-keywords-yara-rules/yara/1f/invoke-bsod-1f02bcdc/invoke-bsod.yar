rule Invoke_BSOD
{
    meta:
        description = "Detection patterns for the tool 'Invoke-BSOD' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-BSOD"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Invoke-BSOD" nocase ascii wide

    condition:
        any of them
}