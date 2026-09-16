rule rule_nirsoft_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nirsoft' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nirsoft"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nirsoft_offensive_tool_keyword = /https\:\/\/www\.nirsoft\.net\/utils\/webcamimagesave\.zip/ nocase ascii wide

    condition:
        any of them
}