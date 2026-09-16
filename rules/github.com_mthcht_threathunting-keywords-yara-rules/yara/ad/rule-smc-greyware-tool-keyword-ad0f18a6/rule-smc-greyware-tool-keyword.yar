rule rule_smc_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'smc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smc"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_smc_greyware_tool_keyword = "smc -disable -mem" nocase ascii wide
                        $string2_smc_greyware_tool_keyword = "smc -disable -ntp" nocase ascii wide
                        $string3_smc_greyware_tool_keyword = "smc -disable -wss" nocase ascii wide
                        $string4_smc_greyware_tool_keyword = "smc -enable -gem" nocase ascii wide
                        $string5_smc_greyware_tool_keyword = /smc\.exe\s\-disable\s\-mem/ nocase ascii wide
                        $string6_smc_greyware_tool_keyword = /smc\.exe\s\-disable\s\-ntp/ nocase ascii wide
                        $string7_smc_greyware_tool_keyword = /smc\.exe\s\-disable\s\-wss/ nocase ascii wide
                        $string8_smc_greyware_tool_keyword = /smc\.exe\s\-enable\s\-gem/ nocase ascii wide

    condition:
        any of them
}