rule rule_Privesc_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Privesc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Privesc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Privesc_offensive_tool_keyword = /\sprivesc\.ps1/ nocase ascii wide
                        $string2_Privesc_offensive_tool_keyword = /\/Privesc\.git/ nocase ascii wide
                        $string3_Privesc_offensive_tool_keyword = /\/privesc\.ps1/ nocase ascii wide
                        $string4_Privesc_offensive_tool_keyword = /\\privesc\.ps1/ nocase ascii wide
                        $string5_Privesc_offensive_tool_keyword = /\\Privesc\-master/ nocase ascii wide
                        $string6_Privesc_offensive_tool_keyword = "enjoiz/Privesc" nocase ascii wide
                        $string7_Privesc_offensive_tool_keyword = "Invoke-Privesc" nocase ascii wide

    condition:
        any of them
}