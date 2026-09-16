rule rule_Augustus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Augustus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Augustus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Augustus_offensive_tool_keyword = /\/3DESEncryptor\.go/ nocase ascii wide
                        $string2_Augustus_offensive_tool_keyword = /\/Augustus\.git/ nocase ascii wide
                        $string3_Augustus_offensive_tool_keyword = /Augustus\-main\.zip/ nocase ascii wide
                        $string4_Augustus_offensive_tool_keyword = "TunnelGRE/Augustus" nocase ascii wide

    condition:
        any of them
}