rule cerbrutus
{
    meta:
        description = "Detection patterns for the tool 'cerbrutus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cerbrutus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/cerbrutus" nocase ascii wide
                        $string2 = /cerbrutus\.py/ nocase ascii wide
                        $string3 = "Cerbrutus-BruteForcer" nocase ascii wide
                        $string4 = /wordlists\/fasttrack\.txt/ nocase ascii wide

    condition:
        any of them
}