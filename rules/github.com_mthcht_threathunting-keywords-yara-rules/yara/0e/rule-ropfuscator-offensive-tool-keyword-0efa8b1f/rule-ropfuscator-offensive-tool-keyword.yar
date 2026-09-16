rule rule_ropfuscator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ropfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ropfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ropfuscator_offensive_tool_keyword = " ropfuscator" nocase ascii wide
                        $string2_ropfuscator_offensive_tool_keyword = "/ropfuscator" nocase ascii wide
                        $string3_ropfuscator_offensive_tool_keyword = /ROPEngine\.cpp/ nocase ascii wide
                        $string4_ropfuscator_offensive_tool_keyword = "ropfuscator " nocase ascii wide
                        $string5_ropfuscator_offensive_tool_keyword = "ROPfuscator" nocase ascii wide
                        $string6_ropfuscator_offensive_tool_keyword = "ropfuscator-" nocase ascii wide
                        $string7_ropfuscator_offensive_tool_keyword = /ropfuscator\./ nocase ascii wide

    condition:
        any of them
}