rule rule_social_engineer_toolkit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'social-engineer-toolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "social-engineer-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_social_engineer_toolkit_offensive_tool_keyword = " setoolkit" nocase ascii wide
                        $string2_social_engineer_toolkit_offensive_tool_keyword = "apt install set -y" nocase ascii wide
                        $string3_social_engineer_toolkit_offensive_tool_keyword = "bin/setoolkit" nocase ascii wide
                        $string4_social_engineer_toolkit_offensive_tool_keyword = "setoolkit " nocase ascii wide
                        $string5_social_engineer_toolkit_offensive_tool_keyword = "Social Engineer Toolkit" nocase ascii wide
                        $string6_social_engineer_toolkit_offensive_tool_keyword = "trustedsec/social-engineer-toolkit" nocase ascii wide

    condition:
        any of them
}