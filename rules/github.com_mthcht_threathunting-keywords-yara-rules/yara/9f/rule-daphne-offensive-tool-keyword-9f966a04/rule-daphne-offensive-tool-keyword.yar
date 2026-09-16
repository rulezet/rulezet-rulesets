rule rule_daphne_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'daphne' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "daphne"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_daphne_offensive_tool_keyword = /\/daphne\.git/ nocase ascii wide
                        $string2_daphne_offensive_tool_keyword = "/daphne-x64" nocase ascii wide
                        $string3_daphne_offensive_tool_keyword = "codewhitesec/daphne" nocase ascii wide
                        $string4_daphne_offensive_tool_keyword = /daphne\-main\.zip/ nocase ascii wide
                        $string5_daphne_offensive_tool_keyword = /daphne\-x64\s.{0,1000}\spid\=/ nocase ascii wide

    condition:
        any of them
}