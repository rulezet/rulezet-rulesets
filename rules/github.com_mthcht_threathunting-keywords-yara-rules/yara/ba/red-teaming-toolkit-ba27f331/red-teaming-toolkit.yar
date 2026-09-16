rule Red_Teaming_Toolkit
{
    meta:
        description = "Detection patterns for the tool 'Red-Teaming-Toolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Red-Teaming-Toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Red-Teaming-Toolkit" nocase ascii wide

    condition:
        any of them
}