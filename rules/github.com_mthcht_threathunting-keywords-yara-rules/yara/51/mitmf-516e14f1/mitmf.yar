rule MITMf
{
    meta:
        description = "Detection patterns for the tool 'MITMf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MITMf"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /MITMf\.py/ nocase ascii wide

    condition:
        any of them
}