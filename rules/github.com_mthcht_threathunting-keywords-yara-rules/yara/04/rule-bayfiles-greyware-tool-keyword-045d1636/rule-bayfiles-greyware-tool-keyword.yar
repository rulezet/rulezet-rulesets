rule rule_bayfiles_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bayfiles' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bayfiles"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_bayfiles_greyware_tool_keyword = /https\:\/\/bayfiles\.com\// nocase ascii wide

    condition:
        any of them
}