rule rule_Xerror_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Xerror' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Xerror"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Xerror_offensive_tool_keyword = "Chudry/Xerror" nocase ascii wide
                        $string2_Xerror_offensive_tool_keyword = "cve_2_MSF_exploit_Mapping" nocase ascii wide
                        $string3_Xerror_offensive_tool_keyword = /mapper_cve_exploit\.py/ nocase ascii wide
                        $string4_Xerror_offensive_tool_keyword = /msf_cve_extracter\.py/ nocase ascii wide
                        $string5_Xerror_offensive_tool_keyword = "nuclei-burp-plugin" nocase ascii wide

    condition:
        any of them
}