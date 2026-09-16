rule rule_pastebin_pl_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pastebin.pl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastebin.pl"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_pastebin_pl_greyware_tool_keyword = /pastebin\.pl\/cdn\-cgi\/challenge\-platform\// nocase ascii wide
                        $string2_pastebin_pl_greyware_tool_keyword = /pastebin\.pl\/view\/raw\// nocase ascii wide

    condition:
        any of them
}