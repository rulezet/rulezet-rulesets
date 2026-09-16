rule browserling
{
    meta:
        description = "Detection patterns for the tool 'browserling' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "browserling"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /https\:\/\/browserling\.com\/tor\-testing/ nocase ascii wide
                        $string2 = /https\:\/\/www\.browserling\.com\/browse/ nocase ascii wide

    condition:
        any of them
}