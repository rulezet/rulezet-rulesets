rule rule_Invoke_ACLpwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ACLpwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ACLpwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_ACLpwn_offensive_tool_keyword = "Invoke-ACLPwn" nocase ascii wide

    condition:
        any of them
}