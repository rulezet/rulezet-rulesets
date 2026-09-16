rule gimmeSH
{
    meta:
        description = "Detection patterns for the tool 'gimmeSH' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gimmeSH"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/gimmeSH/
                        $string2 = /\/gimmeSH\.sh/ nocase ascii wide
                        $string3 = "A3h1nt/gimmeSH" nocase ascii wide

    condition:
        any of them
}