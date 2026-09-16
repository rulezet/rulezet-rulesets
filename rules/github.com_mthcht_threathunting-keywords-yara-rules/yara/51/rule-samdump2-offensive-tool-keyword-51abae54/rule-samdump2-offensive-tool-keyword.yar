rule rule_samdump2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'samdump2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "samdump2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_samdump2_offensive_tool_keyword = "/samdump2" nocase ascii wide
                        $string2_samdump2_offensive_tool_keyword = "install samdump2" nocase ascii wide
                        $string3_samdump2_offensive_tool_keyword = "samdump2 " nocase ascii wide
                        $string4_samdump2_offensive_tool_keyword = /samdump2\.c/ nocase ascii wide

    condition:
        any of them
}