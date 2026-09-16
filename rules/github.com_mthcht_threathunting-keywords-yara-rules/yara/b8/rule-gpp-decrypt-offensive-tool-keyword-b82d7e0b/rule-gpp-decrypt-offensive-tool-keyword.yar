rule rule_gpp_decrypt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gpp-decrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gpp-decrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gpp_decrypt_offensive_tool_keyword = "/gpp-decrypt" nocase ascii wide
                        $string2_gpp_decrypt_offensive_tool_keyword = "apt install gpp-decrypt" nocase ascii wide
                        $string3_gpp_decrypt_offensive_tool_keyword = "gpp-decrypt " nocase ascii wide
                        $string4_gpp_decrypt_offensive_tool_keyword = /gpp\-decrypt\.rb/ nocase ascii wide

    condition:
        any of them
}