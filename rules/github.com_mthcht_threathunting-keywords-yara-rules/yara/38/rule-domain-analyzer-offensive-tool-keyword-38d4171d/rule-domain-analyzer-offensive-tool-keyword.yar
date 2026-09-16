rule rule_domain_analyzer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'domain_analyzer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "domain_analyzer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_domain_analyzer_offensive_tool_keyword = /\scrawler\.py\s\-u\shttp/ nocase ascii wide
                        $string2_domain_analyzer_offensive_tool_keyword = /\/crawler\.py\s\-u\shttp/ nocase ascii wide
                        $string3_domain_analyzer_offensive_tool_keyword = /\/domain_analyzer\.git/ nocase ascii wide
                        $string4_domain_analyzer_offensive_tool_keyword = "/domain_analyzer:latest" nocase ascii wide
                        $string5_domain_analyzer_offensive_tool_keyword = /domain_analyzer\.py/ nocase ascii wide
                        $string6_domain_analyzer_offensive_tool_keyword = "domain_analyzer-master" nocase ascii wide
                        $string7_domain_analyzer_offensive_tool_keyword = "eldraco/domain_analyzer" nocase ascii wide
                        $string8_domain_analyzer_offensive_tool_keyword = "verovaleros/domain_analyzer" nocase ascii wide

    condition:
        any of them
}