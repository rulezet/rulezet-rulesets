rule rule_LdrLockLiberator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LdrLockLiberator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LdrLockLiberator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LdrLockLiberator_offensive_tool_keyword = /\/LdrLockLiberator\.git/ nocase ascii wide
                        $string2_LdrLockLiberator_offensive_tool_keyword = /\\LdrLockLiberator\.c/ nocase ascii wide
                        $string3_LdrLockLiberator_offensive_tool_keyword = /\\LdrLockLiberatorWDK\.c/ nocase ascii wide
                        $string4_LdrLockLiberator_offensive_tool_keyword = "ElliotKillick/LdrLockLiberator" nocase ascii wide
                        $string5_LdrLockLiberator_offensive_tool_keyword = "LdrLockLiberator-main" nocase ascii wide

    condition:
        any of them
}