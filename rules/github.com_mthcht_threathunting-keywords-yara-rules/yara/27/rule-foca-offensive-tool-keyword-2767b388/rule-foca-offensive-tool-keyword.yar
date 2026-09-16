rule rule_FOCA_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FOCA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FOCA"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FOCA_offensive_tool_keyword = /ElevenPaths.{0,1000}FOCA/ nocase ascii wide

    condition:
        any of them
}