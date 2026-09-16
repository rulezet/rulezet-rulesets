rule chcp
{
    meta:
        description = "Detection patterns for the tool 'chcp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chcp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /cmd\.exe\s\/c\schcp\s\>\&2/ nocase ascii wide

    condition:
        any of them
}