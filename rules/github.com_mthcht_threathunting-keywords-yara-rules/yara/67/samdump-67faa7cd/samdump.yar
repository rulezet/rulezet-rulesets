rule samdump
{
    meta:
        description = "Detection patterns for the tool 'samdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "samdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /samdump\.zip/ nocase ascii wide

    condition:
        any of them
}