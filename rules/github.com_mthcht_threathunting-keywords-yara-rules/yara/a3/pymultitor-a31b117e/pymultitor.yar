rule pymultitor
{
    meta:
        description = "Detection patterns for the tool 'pymultitor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pymultitor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "pymultitor" nocase ascii wide

    condition:
        any of them
}