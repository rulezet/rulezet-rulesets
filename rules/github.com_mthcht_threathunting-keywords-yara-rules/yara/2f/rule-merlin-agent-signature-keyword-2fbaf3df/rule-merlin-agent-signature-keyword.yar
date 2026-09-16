rule rule_merlin_agent_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'merlin-agent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin-agent"
        rule_category = "signature_keyword"

    strings:
                        $string1_merlin_agent_signature_keyword = /A\sVariant\sOf\sWinGo\/Merlin\.A/ nocase ascii wide
                        $string2_merlin_agent_signature_keyword = /W64\/Merlin\.T\!tr/ nocase ascii wide
                        $string3_merlin_agent_signature_keyword = "Win64:MerlinAgent" nocase ascii wide

    condition:
        any of them
}