rule rule_SilentHound_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SilentHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SilentHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SilentHound_offensive_tool_keyword = " -k --kerberoast" nocase ascii wide
                        $string2_SilentHound_offensive_tool_keyword = /\/SilentHound\.git/ nocase ascii wide
                        $string3_SilentHound_offensive_tool_keyword = /\-domain_admins\.txt/ nocase ascii wide
                        $string4_SilentHound_offensive_tool_keyword = "layer8secure/SilentHound" nocase ascii wide
                        $string5_SilentHound_offensive_tool_keyword = "Nick Swink aka c0rnbread" nocase ascii wide
                        $string6_SilentHound_offensive_tool_keyword = /silenthound\.py/ nocase ascii wide
                        $string7_SilentHound_offensive_tool_keyword = "SilentHound-main" nocase ascii wide

    condition:
        any of them
}