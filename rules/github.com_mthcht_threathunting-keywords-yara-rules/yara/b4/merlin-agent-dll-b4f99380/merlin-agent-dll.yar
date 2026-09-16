rule merlin_agent_dll
{
    meta:
        description = "Detection patterns for the tool 'merlin-agent-dll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin-agent-dll"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Backdoor\.Merlin/ nocase ascii wide
                        $string2 = "Win64:MerlinAgent" nocase ascii wide

    condition:
        any of them
}