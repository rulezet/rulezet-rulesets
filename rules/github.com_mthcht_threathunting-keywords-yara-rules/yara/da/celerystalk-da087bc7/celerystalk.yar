rule celerystalk
{
    meta:
        description = "Detection patterns for the tool 'celerystalk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "celerystalk"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "celerystalk" nocase ascii wide

    condition:
        any of them
}