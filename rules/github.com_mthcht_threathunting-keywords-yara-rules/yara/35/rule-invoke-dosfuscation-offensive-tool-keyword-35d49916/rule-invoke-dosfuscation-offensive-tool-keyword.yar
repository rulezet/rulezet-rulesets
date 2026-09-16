rule rule_Invoke_DOSfuscation_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-DOSfuscation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-DOSfuscation"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_DOSfuscation_offensive_tool_keyword = "Invoke-DOSfuscation" nocase ascii wide
                        $string2_Invoke_DOSfuscation_offensive_tool_keyword = "Revoke-Obfuscation" nocase ascii wide

    condition:
        any of them
}