rule rule_cerbrutus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cerbrutus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cerbrutus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cerbrutus_offensive_tool_keyword = "/cerbrutus" nocase ascii wide
                        $string2_cerbrutus_offensive_tool_keyword = /cerbrutus\.py/ nocase ascii wide
                        $string3_cerbrutus_offensive_tool_keyword = "Cerbrutus-BruteForcer" nocase ascii wide
                        $string4_cerbrutus_offensive_tool_keyword = /wordlists\/fasttrack\.txt/ nocase ascii wide

    condition:
        any of them
}