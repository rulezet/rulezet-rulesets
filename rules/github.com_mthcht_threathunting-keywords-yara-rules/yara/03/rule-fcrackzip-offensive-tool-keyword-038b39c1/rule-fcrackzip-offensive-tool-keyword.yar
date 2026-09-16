rule rule_fcrackzip_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fcrackzip' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fcrackzip"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fcrackzip_offensive_tool_keyword = /\/usr\/share\/wordlists\/.{0,1000}\.txt/
                        $string2_fcrackzip_offensive_tool_keyword = "fcrackzip " nocase ascii wide

    condition:
        any of them
}