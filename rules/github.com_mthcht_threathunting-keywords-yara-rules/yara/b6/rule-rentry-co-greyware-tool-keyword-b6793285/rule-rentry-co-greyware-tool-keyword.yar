rule rule_rentry_co_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rentry.co' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rentry.co"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_rentry_co_greyware_tool_keyword = /https\:\/\/rentry\.co\// nocase ascii wide
                        $string2_rentry_co_greyware_tool_keyword = /https\:\/\/rentry\.co\/.{0,1000}\/raw/ nocase ascii wide
                        $string3_rentry_co_greyware_tool_keyword = /https\:\/\/rentry\.co\/cdn\-cgi\/challenge\-platform\// nocase ascii wide

    condition:
        any of them
}