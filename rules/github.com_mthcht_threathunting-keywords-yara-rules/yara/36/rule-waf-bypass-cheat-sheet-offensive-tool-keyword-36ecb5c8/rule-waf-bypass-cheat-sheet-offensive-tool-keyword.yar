rule rule_WAF_bypass_Cheat_Sheet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WAF-bypass-Cheat-Sheet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WAF-bypass-Cheat-Sheet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WAF_bypass_Cheat_Sheet_offensive_tool_keyword = "WAF-bypass-Cheat-Sheet" nocase ascii wide

    condition:
        any of them
}