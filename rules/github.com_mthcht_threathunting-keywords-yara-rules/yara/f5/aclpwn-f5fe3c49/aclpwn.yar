rule Aclpwn
{
    meta:
        description = "Detection patterns for the tool 'Aclpwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Aclpwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /aclpwn\.py/ nocase ascii wide

    condition:
        any of them
}