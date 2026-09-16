rule Invoke_Phant0m
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Phant0m' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Phant0m"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Invoke-Phant0m" nocase ascii wide

    condition:
        any of them
}