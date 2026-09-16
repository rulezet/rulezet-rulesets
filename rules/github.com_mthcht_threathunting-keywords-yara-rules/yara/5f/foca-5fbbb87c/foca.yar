rule FOCA
{
    meta:
        description = "Detection patterns for the tool 'FOCA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FOCA"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /ElevenPaths.{0,1000}FOCA/ nocase ascii wide

    condition:
        any of them
}