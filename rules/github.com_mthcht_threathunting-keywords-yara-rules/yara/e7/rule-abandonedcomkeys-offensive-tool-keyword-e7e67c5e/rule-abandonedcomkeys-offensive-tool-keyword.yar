rule rule_AbandonedCOMKeys_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AbandonedCOMKeys' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AbandonedCOMKeys"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AbandonedCOMKeys_offensive_tool_keyword = "/AbandonedCOMKeys/" nocase ascii wide
                        $string2_AbandonedCOMKeys_offensive_tool_keyword = /\\AbandonedCOMKeys\./ nocase ascii wide

    condition:
        any of them
}