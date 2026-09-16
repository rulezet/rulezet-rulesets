rule bayfiles
{
    meta:
        description = "Detection patterns for the tool 'bayfiles' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bayfiles"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/bayfiles\.com\// nocase ascii wide

    condition:
        any of them
}