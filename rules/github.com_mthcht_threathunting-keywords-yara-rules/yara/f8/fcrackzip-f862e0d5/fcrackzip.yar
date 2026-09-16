rule fcrackzip
{
    meta:
        description = "Detection patterns for the tool 'fcrackzip' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fcrackzip"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/usr\/share\/wordlists\/.{0,1000}\.txt/
                        $string2 = "fcrackzip " nocase ascii wide

    condition:
        any of them
}