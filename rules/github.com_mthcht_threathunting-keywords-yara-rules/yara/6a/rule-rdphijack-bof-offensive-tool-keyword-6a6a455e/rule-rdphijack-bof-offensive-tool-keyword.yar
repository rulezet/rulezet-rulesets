rule rule_RDPHijack_BOF_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RDPHijack-BOF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPHijack-BOF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RDPHijack_BOF_offensive_tool_keyword = "beacon_inline_execute" nocase ascii wide
                        $string2_RDPHijack_BOF_offensive_tool_keyword = "bof-rdphijack" nocase ascii wide
                        $string3_RDPHijack_BOF_offensive_tool_keyword = /rdphijack\./ nocase ascii wide
                        $string4_RDPHijack_BOF_offensive_tool_keyword = /rdphijack\.x64\./ nocase ascii wide
                        $string5_RDPHijack_BOF_offensive_tool_keyword = /rdphijack\.x86\./ nocase ascii wide
                        $string6_RDPHijack_BOF_offensive_tool_keyword = "RDPHijack-BOF" nocase ascii wide

    condition:
        any of them
}