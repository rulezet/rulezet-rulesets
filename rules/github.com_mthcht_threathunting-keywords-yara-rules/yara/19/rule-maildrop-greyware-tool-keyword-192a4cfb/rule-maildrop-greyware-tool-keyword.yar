rule rule_maildrop_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'maildrop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "maildrop"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_maildrop_greyware_tool_keyword = /https\:\/\/maildrop\.cc\/inbox\/\?mailbox\=/ nocase ascii wide

    condition:
        any of them
}