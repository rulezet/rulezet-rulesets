rule rule_SMBGhost_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SMBGhost' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBGhost"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SMBGhost_offensive_tool_keyword = /\/SMBGhost\/scanner\.py/ nocase ascii wide
                        $string2_SMBGhost_offensive_tool_keyword = /smb_ghost\.py/ nocase ascii wide
                        $string3_SMBGhost_offensive_tool_keyword = /SMBGhost\.pcap/ nocase ascii wide

    condition:
        any of them
}