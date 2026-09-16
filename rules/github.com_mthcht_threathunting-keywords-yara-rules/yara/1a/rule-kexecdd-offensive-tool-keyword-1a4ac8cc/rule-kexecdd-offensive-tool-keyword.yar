rule rule_KExecDD_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KExecDD' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KExecDD"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KExecDD_offensive_tool_keyword = /\/KExecDD\.git/ nocase ascii wide
                        $string2_KExecDD_offensive_tool_keyword = /\\KExecDD\-main/ nocase ascii wide
                        $string3_KExecDD_offensive_tool_keyword = "0ba663873a7926866e3dd717b970f7e651700d00e9d99f667dfd473eafa81b8a" nocase ascii wide
                        $string4_KExecDD_offensive_tool_keyword = "26085f4768e13063e5dde27f0e313854ce91aa032a7b26d4f57ebc03a6628560" nocase ascii wide
                        $string5_KExecDD_offensive_tool_keyword = "floesen/KExecDD" nocase ascii wide

    condition:
        any of them
}