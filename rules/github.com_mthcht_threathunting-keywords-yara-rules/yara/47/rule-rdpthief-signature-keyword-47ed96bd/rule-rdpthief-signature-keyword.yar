rule rule_RdpThief_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'RdpThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpThief"
        rule_category = "signature_keyword"

    strings:
                        $string1_RdpThief_signature_keyword = /HackTool\.RdpThief/ nocase ascii wide

    condition:
        any of them
}