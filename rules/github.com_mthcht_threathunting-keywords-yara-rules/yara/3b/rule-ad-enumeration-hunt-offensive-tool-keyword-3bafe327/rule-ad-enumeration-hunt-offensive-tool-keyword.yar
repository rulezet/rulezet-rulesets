rule rule_AD_Enumeration_Hunt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AD_Enumeration_Hunt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AD_Enumeration_Hunt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AD_Enumeration_Hunt_offensive_tool_keyword = "/AD_Enumeration_Hunt" nocase ascii wide
                        $string2_AD_Enumeration_Hunt_offensive_tool_keyword = /AD_Enumeration_Hunt\.ps1/ nocase ascii wide
                        $string3_AD_Enumeration_Hunt_offensive_tool_keyword = "AD_Enumeration_Hunt-alperen_ugurlu_hack" nocase ascii wide

    condition:
        any of them
}