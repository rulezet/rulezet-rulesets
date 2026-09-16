rule rule_Private_Internet_Access_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Private Internet Access' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Private Internet Access"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Private_Internet_Access_greyware_tool_keyword = "jplnlifepflhkbkgonidnobkakhmpnmh" nocase ascii wide

    condition:
        any of them
}