rule reapoc
{
    meta:
        description = "Detection patterns for the tool 'reapoc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reapoc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "cckuailong/reapoc" nocase ascii wide

    condition:
        any of them
}