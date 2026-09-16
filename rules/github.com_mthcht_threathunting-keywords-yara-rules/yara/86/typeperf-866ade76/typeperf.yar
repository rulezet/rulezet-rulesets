rule typeperf
{
    meta:
        description = "Detection patterns for the tool 'typeperf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "typeperf"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /typeperf\.exe\s\\"\\System\\Processor\sQueue\sLength\\"\s\-si\s.{0,1000}\s\-sc\s1/ nocase ascii wide

    condition:
        any of them
}