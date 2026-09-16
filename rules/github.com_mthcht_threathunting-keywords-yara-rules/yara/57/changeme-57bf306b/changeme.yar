rule changeme
{
    meta:
        description = "Detection patterns for the tool 'changeme' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "changeme"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /ztgrace.{0,1000}changeme/ nocase ascii wide

    condition:
        any of them
}