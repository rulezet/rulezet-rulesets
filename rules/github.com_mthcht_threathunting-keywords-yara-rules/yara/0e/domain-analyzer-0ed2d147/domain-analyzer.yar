rule domain_analyzer
{
    meta:
        description = "Detection patterns for the tool 'domain_analyzer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "domain_analyzer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scrawler\.py\s\-u\shttp/ nocase ascii wide
                        $string2 = /\/crawler\.py\s\-u\shttp/ nocase ascii wide
                        $string3 = /\/domain_analyzer\.git/ nocase ascii wide
                        $string4 = "/domain_analyzer:latest" nocase ascii wide
                        $string5 = /domain_analyzer\.py/ nocase ascii wide
                        $string6 = "domain_analyzer-master" nocase ascii wide
                        $string7 = "eldraco/domain_analyzer" nocase ascii wide
                        $string8 = "verovaleros/domain_analyzer" nocase ascii wide

    condition:
        any of them
}