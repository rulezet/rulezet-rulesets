rule rule_pywsus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pywsus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pywsus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pywsus_offensive_tool_keyword = /\s\-c\s\'\/accepteula\s\/s\scalc\.exe\'\s\-e\sPsExec64\.exe/ nocase ascii wide
                        $string2_pywsus_offensive_tool_keyword = /\/pywsus\.git/ nocase ascii wide
                        $string3_pywsus_offensive_tool_keyword = /\/pywsus\-master\.zip/ nocase ascii wide
                        $string4_pywsus_offensive_tool_keyword = /pywsus\.py/ nocase ascii wide

    condition:
        any of them
}