rule RdpThief
{
    meta:
        description = "Detection patterns for the tool 'RdpThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpThief"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.RdpThief/ nocase ascii wide

    condition:
        any of them
}