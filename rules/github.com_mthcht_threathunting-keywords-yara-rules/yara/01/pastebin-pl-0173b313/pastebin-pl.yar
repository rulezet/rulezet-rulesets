rule pastebin_pl
{
    meta:
        description = "Detection patterns for the tool 'pastebin.pl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastebin.pl"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /pastebin\.pl\/cdn\-cgi\/challenge\-platform\// nocase ascii wide
                        $string2 = /pastebin\.pl\/view\/raw\// nocase ascii wide

    condition:
        any of them
}