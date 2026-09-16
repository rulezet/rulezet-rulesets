rule rule_LinikatzV2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LinikatzV2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LinikatzV2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LinikatzV2_offensive_tool_keyword = "/LinikatzV2/"
                        $string2_LinikatzV2_offensive_tool_keyword = /\\LinikatzV2\\/
                        $string3_LinikatzV2_offensive_tool_keyword = "kerberos_steal"
                        $string4_LinikatzV2_offensive_tool_keyword = /linikatzV2\.sh/
                        $string5_LinikatzV2_offensive_tool_keyword = "Orange-Cyberdefense/LinikatzV2"
                        $string6_LinikatzV2_offensive_tool_keyword = /SSSDKCMExtractor\.py/

    condition:
        any of them
}