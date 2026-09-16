rule Augustus
{
    meta:
        description = "Detection patterns for the tool 'Augustus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Augustus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/3DESEncryptor\.go/ nocase ascii wide
                        $string2 = /\/Augustus\.git/ nocase ascii wide
                        $string3 = /Augustus\-main\.zip/ nocase ascii wide
                        $string4 = "TunnelGRE/Augustus" nocase ascii wide

    condition:
        any of them
}