rule LinEnum
{
    meta:
        description = "Detection patterns for the tool 'LinEnum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LinEnum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/LinEnum\.git/
                        $string2 = "/LinEnum/"
                        $string3 = /LinEnum\.sh/
                        $string4 = /LinEnum\-master\.ip/

    condition:
        any of them
}