rule w32times
{
    meta:
        description = "Detection patterns for the tool 'w32times' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "w32times"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /w32tm\s\/config\s.{0,1000}\/manualpeerlist\:/ nocase ascii wide

    condition:
        any of them
}