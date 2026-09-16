rule samdump2
{
    meta:
        description = "Detection patterns for the tool 'samdump2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "samdump2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/samdump2" nocase ascii wide
                        $string2 = "install samdump2" nocase ascii wide
                        $string3 = "samdump2 " nocase ascii wide
                        $string4 = /samdump2\.c/ nocase ascii wide

    condition:
        any of them
}