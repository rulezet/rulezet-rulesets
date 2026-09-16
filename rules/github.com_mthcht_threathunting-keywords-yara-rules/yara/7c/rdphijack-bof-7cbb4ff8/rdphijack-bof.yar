rule RDPHijack_BOF
{
    meta:
        description = "Detection patterns for the tool 'RDPHijack-BOF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPHijack-BOF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "beacon_inline_execute" nocase ascii wide
                        $string2 = "bof-rdphijack" nocase ascii wide
                        $string3 = /rdphijack\./ nocase ascii wide
                        $string4 = /rdphijack\.x64\./ nocase ascii wide
                        $string5 = /rdphijack\.x86\./ nocase ascii wide
                        $string6 = "RDPHijack-BOF" nocase ascii wide

    condition:
        any of them
}