rule LdrLockLiberator
{
    meta:
        description = "Detection patterns for the tool 'LdrLockLiberator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LdrLockLiberator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/LdrLockLiberator\.git/ nocase ascii wide
                        $string2 = /\\LdrLockLiberator\.c/ nocase ascii wide
                        $string3 = /\\LdrLockLiberatorWDK\.c/ nocase ascii wide
                        $string4 = "ElliotKillick/LdrLockLiberator" nocase ascii wide
                        $string5 = "LdrLockLiberator-main" nocase ascii wide

    condition:
        any of them
}