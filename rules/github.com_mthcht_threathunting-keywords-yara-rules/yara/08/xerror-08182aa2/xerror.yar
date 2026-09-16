rule Xerror
{
    meta:
        description = "Detection patterns for the tool 'Xerror' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Xerror"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Chudry/Xerror" nocase ascii wide
                        $string2 = "cve_2_MSF_exploit_Mapping" nocase ascii wide
                        $string3 = /mapper_cve_exploit\.py/ nocase ascii wide
                        $string4 = /msf_cve_extracter\.py/ nocase ascii wide
                        $string5 = "nuclei-burp-plugin" nocase ascii wide

    condition:
        any of them
}