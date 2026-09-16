rule lsass
{
    meta:
        description = "Detection patterns for the tool 'lsass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /lsass\.dmp/ nocase ascii wide

    condition:
        any of them
}