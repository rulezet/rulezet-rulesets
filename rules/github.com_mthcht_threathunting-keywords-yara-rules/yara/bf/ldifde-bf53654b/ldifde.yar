rule ldifde
{
    meta:
        description = "Detection patterns for the tool 'ldifde' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldifde"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /ldifde\.exe\s\-f\s.{0,1000}\\temp\\.{0,1000}\.txt\s\-p\ssubtree/ nocase ascii wide

    condition:
        any of them
}