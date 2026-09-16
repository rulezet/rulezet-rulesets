rule privnote_com
{
    meta:
        description = "Detection patterns for the tool 'privnote.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "privnote.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/privnote\.com\// nocase ascii wide

    condition:
        any of them
}