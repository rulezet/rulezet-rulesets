rule SMBGhost
{
    meta:
        description = "Detection patterns for the tool 'SMBGhost' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBGhost"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SMBGhost\/scanner\.py/ nocase ascii wide
                        $string2 = /smb_ghost\.py/ nocase ascii wide
                        $string3 = /SMBGhost\.pcap/ nocase ascii wide

    condition:
        any of them
}