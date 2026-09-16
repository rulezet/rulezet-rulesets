rule rule_badtouch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'badtouch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "badtouch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_badtouch_offensive_tool_keyword = "kpcyrd/badtouch" nocase ascii wide

    condition:
        any of them
}