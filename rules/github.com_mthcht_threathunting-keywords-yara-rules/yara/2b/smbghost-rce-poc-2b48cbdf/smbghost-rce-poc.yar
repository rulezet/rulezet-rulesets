rule SMBGhost_RCE_PoC
{
    meta:
        description = "Detection patterns for the tool 'SMBGhost_RCE_PoC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBGhost_RCE_PoC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/SMBGhost_RCE" nocase ascii wide
                        $string2 = /smb_win\.py/ nocase ascii wide

    condition:
        any of them
}