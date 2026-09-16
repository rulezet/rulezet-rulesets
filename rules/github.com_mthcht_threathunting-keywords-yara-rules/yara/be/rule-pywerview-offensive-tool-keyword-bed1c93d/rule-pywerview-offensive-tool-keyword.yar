rule rule_pywerview_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pywerview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pywerview"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pywerview_offensive_tool_keyword = "/pywerview" nocase ascii wide
                        $string2_pywerview_offensive_tool_keyword = "invoke-checklocaladminaccess" nocase ascii wide
                        $string3_pywerview_offensive_tool_keyword = "invoke-eventhunter" nocase ascii wide
                        $string4_pywerview_offensive_tool_keyword = "invoke-processhunter" nocase ascii wide
                        $string5_pywerview_offensive_tool_keyword = "invoke-userhunter" nocase ascii wide
                        $string6_pywerview_offensive_tool_keyword = /pywerview\.py/ nocase ascii wide

    condition:
        any of them
}