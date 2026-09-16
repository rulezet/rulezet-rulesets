rule rule_wget_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wget' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wget"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_wget_greyware_tool_keyword = /wget\s\-O\s\-\s\-q\shttp\:\/\/.{0,1000}\.jpg\|sh/
                        $string2_wget_greyware_tool_keyword = /wget\s\-O\s\-\s\-q\shttps\:\/\/.{0,1000}\.jpg\|sh/

    condition:
        any of them
}