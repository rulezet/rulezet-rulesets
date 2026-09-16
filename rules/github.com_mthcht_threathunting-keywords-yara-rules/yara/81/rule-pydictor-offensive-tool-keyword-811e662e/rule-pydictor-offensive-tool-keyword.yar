rule rule_pydictor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pydictor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pydictor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pydictor_offensive_tool_keyword = "pydictor" nocase ascii wide

    condition:
        any of them
}