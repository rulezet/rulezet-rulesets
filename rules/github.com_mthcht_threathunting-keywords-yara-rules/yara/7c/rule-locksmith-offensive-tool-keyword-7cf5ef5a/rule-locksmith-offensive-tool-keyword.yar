rule rule_Locksmith_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Locksmith' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Locksmith"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Locksmith_offensive_tool_keyword = /\s\-InputPath\s\.\\TrustedForests\.txt/ nocase ascii wide
                        $string2_Locksmith_offensive_tool_keyword = /\/Locksmith\.git/ nocase ascii wide
                        $string3_Locksmith_offensive_tool_keyword = /Invoke\-Locksmith\.ps1/ nocase ascii wide
                        $string4_Locksmith_offensive_tool_keyword = /Locksmith\-main\.zip/ nocase ascii wide

    condition:
        any of them
}