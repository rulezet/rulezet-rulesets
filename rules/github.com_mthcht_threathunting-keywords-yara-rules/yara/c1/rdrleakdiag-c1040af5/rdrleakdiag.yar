rule rdrleakdiag
{
    meta:
        description = "Detection patterns for the tool 'rdrleakdiag' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdrleakdiag"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /rdrleakdiag\.exe\s\/p\s.{0,1000}\s\/o\s.{0,1000}\s\/fullmemdmp\s\/wait\s1/ nocase ascii wide

    condition:
        any of them
}